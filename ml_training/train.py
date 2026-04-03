"""
ML Training Pipeline – Model Training.

Trains three complementary models:

* :class:`~sklearn.ensemble.RandomForestClassifier`  – supervised multi-class.
* :class:`~sklearn.ensemble.IsolationForest`          – unsupervised anomaly detection.
* :class:`xgboost.XGBClassifier`                     – gradient-boosted ensemble.

Hyperparameter tuning
---------------------
:func:`tune_random_forest` and :func:`tune_xgboost` run
:class:`~sklearn.model_selection.GridSearchCV` on a small parameter grid.
For large datasets, consider reducing ``cv`` folds or switching to
``RandomizedSearchCV``.

K-fold cross-validation
-----------------------
:func:`cross_validate_model` returns per-fold metrics for any estimator.

Persistence
-----------
Models, the scaler, and feature names are saved to ``ml_training/models/``
with :mod:`joblib` so they can be loaded by the firewall engine.

Logging
-------
All major milestones and metrics are emitted via the standard
:mod:`logging` module.  Configure the root logger before calling these
functions to capture output.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.model_selection import GridSearchCV, StratifiedKFold, cross_validate
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

_MODELS_DIR = Path("ml_training/models")
_DEFAULT_CV_FOLDS = 5
_DEFAULT_RANDOM_STATE = 42

_RF_PARAM_GRID: dict[str, list[Any]] = {
    "n_estimators": [100, 300],
    "max_depth": [None, 15, 30],
    "min_samples_split": [2, 5],
    "class_weight": ["balanced", None],
}

_XGB_PARAM_GRID: dict[str, list[Any]] = {
    "n_estimators": [100, 300],
    "max_depth": [4, 6, 8],
    "learning_rate": [0.05, 0.1, 0.2],
    "subsample": [0.8, 1.0],
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _elapsed(start: float) -> str:
    return f"{time.time() - start:.1f}s"


def _save(obj: Any, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(obj, path)
    logger.info("Saved → %s", path)


# ---------------------------------------------------------------------------
# RandomForest
# ---------------------------------------------------------------------------

def train_random_forest(
    X_train: np.ndarray,
    y_train: np.ndarray,
    n_estimators: int = 300,
    max_depth: int | None = None,
    class_weight: str | None = "balanced",
    random_state: int = _DEFAULT_RANDOM_STATE,
    n_jobs: int = -1,
) -> RandomForestClassifier:
    """
    Train a :class:`~sklearn.ensemble.RandomForestClassifier`.

    Parameters
    ----------
    X_train, y_train:
        Scaled feature matrix and integer label vector.
    n_estimators:
        Number of trees.
    max_depth:
        Maximum tree depth (``None`` = unlimited).
    class_weight:
        ``"balanced"`` to handle class imbalance automatically.

    Returns
    -------
    Fitted :class:`~sklearn.ensemble.RandomForestClassifier`.
    """
    logger.info(
        "Training RandomForest (n_estimators=%d, max_depth=%s, class_weight=%s)",
        n_estimators, max_depth, class_weight,
    )
    t0 = time.time()
    rf = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        class_weight=class_weight,
        random_state=random_state,
        n_jobs=n_jobs,
    )
    rf.fit(X_train, y_train)
    logger.info("RandomForest trained in %s", _elapsed(t0))
    return rf


def tune_random_forest(
    X_train: np.ndarray,
    y_train: np.ndarray,
    param_grid: dict[str, list[Any]] | None = None,
    cv: int = _DEFAULT_CV_FOLDS,
    scoring: str = "f1_weighted",
    random_state: int = _DEFAULT_RANDOM_STATE,
    n_jobs: int = -1,
) -> RandomForestClassifier:
    """
    Tune a RandomForest via :class:`~sklearn.model_selection.GridSearchCV`.

    Returns
    -------
    Best estimator after cross-validated grid search.
    """
    grid = param_grid or _RF_PARAM_GRID
    logger.info(
        "GridSearchCV for RandomForest (%d folds, scoring=%s)", cv, scoring
    )
    t0 = time.time()
    gscv = GridSearchCV(
        RandomForestClassifier(random_state=random_state, n_jobs=n_jobs),
        param_grid=grid,
        cv=StratifiedKFold(n_splits=cv, shuffle=True, random_state=random_state),
        scoring=scoring,
        n_jobs=n_jobs,
        verbose=1,
        refit=True,
    )
    gscv.fit(X_train, y_train)
    logger.info(
        "RF GridSearch done in %s – best params: %s  best score: %.4f",
        _elapsed(t0), gscv.best_params_, gscv.best_score_,
    )
    return gscv.best_estimator_


# ---------------------------------------------------------------------------
# IsolationForest
# ---------------------------------------------------------------------------

def train_isolation_forest(
    X_train: np.ndarray,
    contamination: float = 0.05,
    n_estimators: int = 200,
    random_state: int = _DEFAULT_RANDOM_STATE,
    n_jobs: int = -1,
) -> IsolationForest:
    """
    Train an :class:`~sklearn.ensemble.IsolationForest` for anomaly detection.

    Parameters
    ----------
    contamination:
        Estimated fraction of anomalies in the training set.

    Returns
    -------
    Fitted :class:`~sklearn.ensemble.IsolationForest`.

    Notes
    -----
    ``predict()`` returns ``+1`` for *normal* samples and ``-1`` for
    *anomalies*.  Use ``score_samples()`` to obtain a raw anomaly score
    (lower = more anomalous).
    """
    logger.info(
        "Training IsolationForest (n_estimators=%d, contamination=%.3f)",
        n_estimators, contamination,
    )
    t0 = time.time()
    iso = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=random_state,
        n_jobs=n_jobs,
    )
    iso.fit(X_train)
    logger.info("IsolationForest trained in %s", _elapsed(t0))
    return iso


# ---------------------------------------------------------------------------
# XGBoost
# ---------------------------------------------------------------------------

def train_xgboost(
    X_train: np.ndarray,
    y_train: np.ndarray,
    n_estimators: int = 300,
    max_depth: int = 6,
    learning_rate: float = 0.1,
    subsample: float = 0.8,
    eval_set: tuple[np.ndarray, np.ndarray] | None = None,
    random_state: int = _DEFAULT_RANDOM_STATE,
) -> Any:
    """
    Train an :class:`xgboost.XGBClassifier`.

    Returns
    -------
    Fitted :class:`xgboost.XGBClassifier`, or a :class:`RandomForestClassifier`
    fallback when XGBoost is not installed.
    """
    try:
        from xgboost import XGBClassifier
    except ImportError:
        logger.warning("xgboost not installed – falling back to RandomForest")
        return train_random_forest(X_train, y_train, random_state=random_state)

    n_classes = len(np.unique(y_train))
    objective = "multi:softprob" if n_classes > 2 else "binary:logistic"
    eval_metric = "mlogloss" if n_classes > 2 else "logloss"

    logger.info(
        "Training XGBClassifier (n_estimators=%d, max_depth=%d, lr=%.3f)",
        n_estimators, max_depth, learning_rate,
    )
    t0 = time.time()
    xgb = XGBClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        learning_rate=learning_rate,
        subsample=subsample,
        objective=objective,
        eval_metric=eval_metric,
        random_state=random_state,
        n_jobs=-1,
        verbosity=1,
    )
    fit_kwargs: dict[str, Any] = {}
    if eval_set is not None:
        fit_kwargs["eval_set"] = [eval_set]
        fit_kwargs["verbose"] = False

    xgb.fit(X_train, y_train, **fit_kwargs)
    logger.info("XGBClassifier trained in %s", _elapsed(t0))
    return xgb


def tune_xgboost(
    X_train: np.ndarray,
    y_train: np.ndarray,
    param_grid: dict[str, list[Any]] | None = None,
    cv: int = _DEFAULT_CV_FOLDS,
    scoring: str = "f1_weighted",
    random_state: int = _DEFAULT_RANDOM_STATE,
) -> Any:
    """
    Tune an XGBClassifier via GridSearchCV.

    Falls back to tuning a RandomForest if XGBoost is not available.
    """
    try:
        from xgboost import XGBClassifier
    except ImportError:
        logger.warning("xgboost not installed – tuning RandomForest instead")
        return tune_random_forest(
            X_train, y_train, cv=cv, scoring=scoring, random_state=random_state
        )

    n_classes = len(np.unique(y_train))
    objective = "multi:softprob" if n_classes > 2 else "binary:logistic"
    grid = param_grid or _XGB_PARAM_GRID

    logger.info("GridSearchCV for XGBoost (%d folds, scoring=%s)", cv, scoring)
    t0 = time.time()
    gscv = GridSearchCV(
        XGBClassifier(
            objective=objective,
            random_state=random_state,
            n_jobs=-1,
            verbosity=0,
        ),
        param_grid=grid,
        cv=StratifiedKFold(n_splits=cv, shuffle=True, random_state=random_state),
        scoring=scoring,
        n_jobs=-1,
        verbose=1,
        refit=True,
    )
    gscv.fit(X_train, y_train)
    logger.info(
        "XGB GridSearch done in %s – best params: %s  best score: %.4f",
        _elapsed(t0), gscv.best_params_, gscv.best_score_,
    )
    return gscv.best_estimator_


# ---------------------------------------------------------------------------
# K-fold cross-validation
# ---------------------------------------------------------------------------

def cross_validate_model(
    estimator: Any,
    X: np.ndarray,
    y: np.ndarray,
    cv: int = _DEFAULT_CV_FOLDS,
    scoring: tuple[str, ...] = ("accuracy", "f1_weighted", "roc_auc_ovr_weighted"),
    random_state: int = _DEFAULT_RANDOM_STATE,
) -> dict[str, Any]:
    """
    Run stratified K-fold cross-validation and return aggregated metrics.

    Returns
    -------
    Dict mapping each metric name to ``{"mean": float, "std": float,
    "folds": list[float]}``.
    """
    logger.info("Cross-validating %s (%d folds)", type(estimator).__name__, cv)
    t0 = time.time()

    # roc_auc requires predict_proba; skip if not supported.
    valid_scoring = list(scoring)
    if not hasattr(estimator, "predict_proba"):
        valid_scoring = [s for s in valid_scoring if "roc_auc" not in s]

    cv_results = cross_validate(
        estimator,
        X,
        y,
        cv=StratifiedKFold(n_splits=cv, shuffle=True, random_state=random_state),
        scoring=valid_scoring,
        return_train_score=False,
        n_jobs=-1,
    )

    summary: dict[str, Any] = {}
    for metric in valid_scoring:
        key = f"test_{metric}"
        if key in cv_results:
            scores = cv_results[key].tolist()
            summary[metric] = {
                "mean": float(np.mean(scores)),
                "std": float(np.std(scores)),
                "folds": scores,
            }
            logger.info("  %s: %.4f ± %.4f", metric, summary[metric]["mean"], summary[metric]["std"])

    logger.info("Cross-validation done in %s", _elapsed(t0))
    return summary


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def save_models(
    output_dir: str | Path = _MODELS_DIR,
    random_forest: RandomForestClassifier | None = None,
    isolation_forest: IsolationForest | None = None,
    xgboost_clf: Any = None,
    scaler: StandardScaler | None = None,
    feature_names: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    """
    Save trained models and associated artefacts to *output_dir*.

    Written files (only for non-None arguments):
    ``random_forest.joblib``, ``isolation_forest.joblib``,
    ``xgboost_clf.joblib``, ``scaler.joblib``, ``feature_names.json``,
    ``training_metadata.json``.
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    if random_forest is not None:
        _save(random_forest, out / "random_forest.joblib")
    if isolation_forest is not None:
        _save(isolation_forest, out / "isolation_forest.joblib")
    if xgboost_clf is not None:
        _save(xgboost_clf, out / "xgboost_clf.joblib")
    if scaler is not None:
        _save(scaler, out / "scaler.joblib")
    if feature_names is not None:
        with (out / "feature_names.json").open("w") as fh:
            json.dump(feature_names, fh, indent=2)
        logger.info("Saved feature_names.json (%d features)", len(feature_names))
    if metadata is not None:
        with (out / "training_metadata.json").open("w") as fh:
            json.dump(metadata, fh, indent=2, default=str)
        logger.info("Saved training_metadata.json")


# ---------------------------------------------------------------------------
# High-level training pipeline
# ---------------------------------------------------------------------------

def run_training(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    feature_names: list[str],
    scaler: StandardScaler,
    models_dir: str | Path = _MODELS_DIR,
    tune: bool = False,
    cv_folds: int = _DEFAULT_CV_FOLDS,
    random_state: int = _DEFAULT_RANDOM_STATE,
) -> dict[str, Any]:
    """
    Execute the full training pipeline.

    Parameters
    ----------
    tune:
        If ``True``, run GridSearchCV for RF and XGBoost (slow).

    Returns
    -------
    Dict with trained model objects and cross-validation summaries.
    """
    logger.info("=== Training pipeline start ===")
    t_total = time.time()

    # --- RandomForest ---
    if tune:
        rf = tune_random_forest(X_train, y_train, cv=cv_folds, random_state=random_state)
    else:
        rf = train_random_forest(X_train, y_train, random_state=random_state)
    rf_cv = cross_validate_model(rf, X_train, y_train, cv=cv_folds, random_state=random_state)

    # --- IsolationForest ---
    iso = train_isolation_forest(X_train, random_state=random_state)

    # --- XGBoost ---
    if tune:
        xgb = tune_xgboost(X_train, y_train, cv=cv_folds, random_state=random_state)
    else:
        xgb = train_xgboost(
            X_train, y_train,
            eval_set=(X_val, y_val),
            random_state=random_state,
        )
    xgb_cv = cross_validate_model(xgb, X_train, y_train, cv=cv_folds, random_state=random_state)

    metadata: dict[str, Any] = {
        "train_samples": int(X_train.shape[0]),
        "n_features": int(X_train.shape[1]),
        "n_classes": int(len(np.unique(y_train))),
        "random_forest_cv": rf_cv,
        "xgboost_cv": xgb_cv,
        "tuned": tune,
        "total_training_time_s": round(time.time() - t_total, 1),
    }

    save_models(
        output_dir=models_dir,
        random_forest=rf,
        isolation_forest=iso,
        xgboost_clf=xgb,
        scaler=scaler,
        feature_names=feature_names,
        metadata=metadata,
    )

    logger.info("=== Training pipeline complete in %s ===", _elapsed(t_total))
    return {
        "random_forest": rf,
        "isolation_forest": iso,
        "xgboost": xgb,
        "rf_cv": rf_cv,
        "xgb_cv": xgb_cv,
        "metadata": metadata,
    }
