"""
ML Training Pipeline – Feature Selection.

Implements four complementary strategies:

1. **RandomForest importance** – mean decrease in impurity across all trees.
2. **SelectKBest** – univariate scoring using mutual information.
3. **Recursive Feature Elimination (RFE)** – iterative backward elimination
   driven by a :class:`~sklearn.ensemble.RandomForestClassifier`.
4. **Correlation-based pruning** – removes one feature from each highly
   correlated pair (Pearson |r| ≥ threshold).

All selectors can be combined via :func:`select_features`, which returns the
union/intersection of selected feature names and a ranked DataFrame suitable
for reporting and visualisation.

Results are persisted to ``selected_features.json`` so downstream modules
(training, inference) always use the same feature set.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import (
    RFE,
    SelectKBest,
    mutual_info_classif,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

_DEFAULT_K = 20          # Top-K for SelectKBest
_DEFAULT_N_ESTIMATORS = 100
_DEFAULT_CORR_THRESHOLD = 0.95


# ---------------------------------------------------------------------------
# Strategy 1 – RandomForest feature importances
# ---------------------------------------------------------------------------

def rf_importances(
    X: np.ndarray,
    y: np.ndarray,
    feature_names: list[str],
    n_estimators: int = _DEFAULT_N_ESTIMATORS,
    random_state: int = 42,
    top_k: int | None = None,
) -> pd.DataFrame:
    """
    Compute mean decrease-in-impurity importance from a RandomForest.

    Parameters
    ----------
    X, y:
        Training features and labels.
    feature_names:
        Column names corresponding to *X* columns.
    n_estimators:
        Number of trees in the forest.
    top_k:
        If given, return only the *top_k* most important features.

    Returns
    -------
    DataFrame with columns ``feature``, ``rf_importance`` sorted descending.
    """
    logger.info("Computing RandomForest feature importances (n_estimators=%d)", n_estimators)
    rf = RandomForestClassifier(
        n_estimators=n_estimators,
        n_jobs=-1,
        random_state=random_state,
    )
    rf.fit(X, y)
    importances = rf.feature_importances_

    df = pd.DataFrame({"feature": feature_names, "rf_importance": importances})
    df = df.sort_values("rf_importance", ascending=False).reset_index(drop=True)
    if top_k is not None:
        df = df.head(top_k)
    logger.info("RF importances computed for %d features", len(df))
    return df


# ---------------------------------------------------------------------------
# Strategy 2 – SelectKBest with mutual information
# ---------------------------------------------------------------------------

def kbest_mutual_info(
    X: np.ndarray,
    y: np.ndarray,
    feature_names: list[str],
    k: int = _DEFAULT_K,
    random_state: int = 42,
) -> pd.DataFrame:
    """
    Select *k* best features using mutual information criterion.

    Returns
    -------
    DataFrame with columns ``feature``, ``mi_score`` for the *k* selected
    features, sorted descending.
    """
    logger.info("Running SelectKBest(mutual_info_classif, k=%d)", k)
    k = min(k, X.shape[1])
    selector = SelectKBest(
        score_func=lambda _X, _y: mutual_info_classif(_X, _y, random_state=random_state),
        k=k,
    )
    selector.fit(X, y)
    scores = selector.scores_

    df = pd.DataFrame({"feature": feature_names, "mi_score": scores})
    df = df.sort_values("mi_score", ascending=False).reset_index(drop=True)
    df = df.head(k)
    logger.info("SelectKBest selected %d features", len(df))
    return df


# ---------------------------------------------------------------------------
# Strategy 3 – Recursive Feature Elimination
# ---------------------------------------------------------------------------

def rfe_selection(
    X: np.ndarray,
    y: np.ndarray,
    feature_names: list[str],
    n_features_to_select: int = _DEFAULT_K,
    n_estimators: int = _DEFAULT_N_ESTIMATORS,
    random_state: int = 42,
) -> pd.DataFrame:
    """
    Perform Recursive Feature Elimination using a RandomForest estimator.

    Returns
    -------
    DataFrame with columns ``feature``, ``rfe_ranking`` for *all* features,
    filtered to those actually selected (``rfe_ranking == 1``), sorted by
    ranking.
    """
    logger.info(
        "Running RFE (n_features_to_select=%d, n_estimators=%d)",
        n_features_to_select, n_estimators,
    )
    n_features_to_select = min(n_features_to_select, X.shape[1])
    estimator = RandomForestClassifier(
        n_estimators=n_estimators,
        n_jobs=-1,
        random_state=random_state,
    )
    rfe = RFE(estimator=estimator, n_features_to_select=n_features_to_select, step=0.1)
    rfe.fit(X, y)

    df = pd.DataFrame({"feature": feature_names, "rfe_ranking": rfe.ranking_})
    df = df[df["rfe_ranking"] == 1].sort_values("rfe_ranking").reset_index(drop=True)
    logger.info("RFE retained %d features", len(df))
    return df


# ---------------------------------------------------------------------------
# Strategy 4 – Correlation-based pruning
# ---------------------------------------------------------------------------

def correlation_pruning(
    X: np.ndarray,
    feature_names: list[str],
    threshold: float = _DEFAULT_CORR_THRESHOLD,
) -> list[str]:
    """
    Remove one feature from each pair whose Pearson |r| ≥ *threshold*.

    The feature occurring *later* in column order is dropped (arbitrary but
    reproducible).

    Returns
    -------
    List of feature names that survive pruning.
    """
    logger.info("Running correlation-based pruning (threshold=%.2f)", threshold)
    df = pd.DataFrame(X, columns=feature_names)
    corr_matrix = df.corr().abs()

    upper = corr_matrix.where(
        np.triu(np.ones(corr_matrix.shape, dtype=bool), k=1)
    )
    to_drop = {col for col in upper.columns if (upper[col] > threshold).any()}
    survivors = [f for f in feature_names if f not in to_drop]

    logger.info(
        "Correlation pruning: %d → %d features (%d dropped)",
        len(feature_names), len(survivors), len(to_drop),
    )
    return survivors


# ---------------------------------------------------------------------------
# Unified selector
# ---------------------------------------------------------------------------

def select_features(
    X_train: np.ndarray,
    y_train: np.ndarray,
    feature_names: list[str],
    top_k: int = _DEFAULT_K,
    use_rf: bool = True,
    use_kbest: bool = True,
    use_rfe: bool = True,
    use_corr: bool = True,
    corr_threshold: float = _DEFAULT_CORR_THRESHOLD,
    combination: str = "union",
    random_state: int = 42,
) -> tuple[list[str], pd.DataFrame]:
    """
    Run all enabled feature selection strategies and combine results.

    Parameters
    ----------
    combination:
        How to combine the individual selector outputs:
        ``"union"`` – any feature selected by *at least one* strategy.
        ``"intersection"`` – only features selected by *all* strategies.

    Returns
    -------
    ``(selected_names, ranking_df)``
        * ``selected_names`` – final list of selected feature names.
        * ``ranking_df``     – merged DataFrame with per-strategy scores
          and an ``aggregate_rank`` column.
    """
    results: dict[str, pd.DataFrame] = {}
    sets: list[set[str]] = []

    if use_rf:
        rf_df = rf_importances(X_train, y_train, feature_names, top_k=top_k, random_state=random_state)
        results["rf"] = rf_df
        sets.append(set(rf_df["feature"].tolist()))

    if use_kbest:
        kb_df = kbest_mutual_info(X_train, y_train, feature_names, k=top_k, random_state=random_state)
        results["kbest"] = kb_df
        sets.append(set(kb_df["feature"].tolist()))

    if use_rfe:
        rfe_df = rfe_selection(
            X_train, y_train, feature_names,
            n_features_to_select=top_k,
            random_state=random_state,
        )
        results["rfe"] = rfe_df
        sets.append(set(rfe_df["feature"].tolist()))

    if use_corr:
        survivors = correlation_pruning(X_train, feature_names, threshold=corr_threshold)
        # Corr pruning gives a *negative* selection (what NOT to include).
        # Intersect existing sets with survivors to enforce the constraint.
        sets = [s & set(survivors) for s in sets] if sets else [set(survivors)]

    if not sets:
        logger.warning("No selection strategy enabled – returning all features")
        return feature_names, pd.DataFrame({"feature": feature_names})

    if combination == "intersection":
        selected_set = set.intersection(*sets)
    else:
        selected_set = set.union(*sets)

    # Preserve original column order
    selected_names = [f for f in feature_names if f in selected_set]

    # Build a merged ranking DataFrame
    ranking_df = _build_ranking_df(feature_names, results, selected_set)

    logger.info(
        "Feature selection (%s): %d → %d features",
        combination, len(feature_names), len(selected_names),
    )
    return selected_names, ranking_df


def _build_ranking_df(
    feature_names: list[str],
    results: dict[str, pd.DataFrame],
    selected_set: set[str],
) -> pd.DataFrame:
    """Merge per-strategy scores into a single ranking DataFrame."""
    base = pd.DataFrame({"feature": feature_names})
    for strategy, df in results.items():
        score_col = next((c for c in df.columns if c != "feature"), None)
        if score_col:
            base = base.merge(df[["feature", score_col]], on="feature", how="left")

    base["selected"] = base["feature"].isin(selected_set)

    # Aggregate rank: mean of available score columns (normalised 0-1).
    score_cols = [c for c in base.columns if c not in ("feature", "selected")]
    if score_cols:
        for col in score_cols:
            col_min = base[col].min()
            col_max = base[col].max()
            denom = col_max - col_min if col_max != col_min else 1.0
            base[col] = (base[col] - col_min) / denom
        base["aggregate_rank"] = base[score_cols].mean(axis=1)
        base = base.sort_values("aggregate_rank", ascending=False).reset_index(drop=True)

    return base


# ---------------------------------------------------------------------------
# Persistence & visualisation
# ---------------------------------------------------------------------------

def save_selected_features(
    selected_names: list[str],
    ranking_df: pd.DataFrame,
    output_dir: str | Path = "ml_training/data/preprocessed",
) -> None:
    """
    Persist selected feature names and ranking report to *output_dir*.

    Written files
    -------------
    ``selected_features.json`` – ordered list of selected feature names.
    ``feature_ranking.csv``    – full ranking DataFrame.
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    with (out / "selected_features.json").open("w") as fh:
        json.dump(selected_names, fh, indent=2)
    ranking_df.to_csv(out / "feature_ranking.csv", index=False)
    logger.info("Saved %d selected features to %s", len(selected_names), out)


def plot_feature_importance(
    ranking_df: pd.DataFrame,
    top_n: int = 20,
    output_path: str | Path | None = None,
) -> Any:
    """
    Bar plot of the top-*n* features by aggregate rank.

    Parameters
    ----------
    output_path:
        If given, save the figure instead of (or in addition to) returning it.

    Returns
    -------
    Matplotlib :class:`~matplotlib.figure.Figure`, or ``None`` if matplotlib
    is not available.
    """
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import seaborn as sns
    except ImportError:
        logger.warning("matplotlib/seaborn not installed; skipping plot")
        return None

    plot_df = ranking_df[ranking_df["selected"]].head(top_n)
    if "aggregate_rank" not in plot_df.columns:
        logger.warning("No aggregate_rank column found; cannot plot")
        return None

    fig, ax = plt.subplots(figsize=(10, max(6, top_n // 2)))
    sns.barplot(
        data=plot_df,
        x="aggregate_rank",
        y="feature",
        palette="viridis",
        ax=ax,
    )
    ax.set_title(f"Top-{len(plot_df)} Feature Importance (aggregate)")
    ax.set_xlabel("Normalised aggregate score")
    ax.set_ylabel("Feature")
    fig.tight_layout()

    if output_path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        fig.savefig(out, dpi=150)
        logger.info("Feature importance plot saved to %s", out)

    return fig
