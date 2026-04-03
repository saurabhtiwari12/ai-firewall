"""
ML Training Pipeline – Model Evaluation.

Computes a comprehensive set of metrics for trained classifiers and supports
A/B comparison between two model versions.

Metrics computed
----------------
* Accuracy, Precision, Recall, F1-score (macro, micro, weighted)
* AUC-ROC (one-vs-rest, weighted)
* Confusion matrix
* Per-class precision, recall, F1, support

A/B testing
-----------
:func:`ab_test` compares two models on the same held-out test set and
produces a structured report showing which model wins on each metric.

Reports
-------
:func:`save_evaluation_report` writes a human-readable JSON report to
``ml_training/reports/``.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MODELS_DIR = Path("ml_training/models")
_REPORTS_DIR = Path("ml_training/reports")


# ---------------------------------------------------------------------------
# Model loading
# ---------------------------------------------------------------------------

def load_model(path: str | Path) -> Any:
    """
    Load a joblib-serialised model from *path*.

    Raises
    ------
    FileNotFoundError
        If the file does not exist.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Model not found: {path}")
    model = joblib.load(path)
    logger.info("Loaded model from %s", path)
    return model


def load_evaluation_artefacts(
    models_dir: str | Path = _MODELS_DIR,
) -> dict[str, Any]:
    """
    Load all models and the scaler from *models_dir*.

    Returns a dict with keys: ``random_forest``, ``isolation_forest``,
    ``xgboost``, ``scaler``, ``feature_names``.  Missing files are silently
    skipped (key set to ``None``).
    """
    d = Path(models_dir)
    artefacts: dict[str, Any] = {}
    for key, filename in [
        ("random_forest", "random_forest.joblib"),
        ("isolation_forest", "isolation_forest.joblib"),
        ("xgboost", "xgboost_clf.joblib"),
        ("scaler", "scaler.joblib"),
    ]:
        fp = d / filename
        artefacts[key] = joblib.load(fp) if fp.exists() else None

    fn_path = d / "feature_names.json"
    if fn_path.exists():
        with fn_path.open() as fh:
            artefacts["feature_names"] = json.load(fh)
    else:
        artefacts["feature_names"] = None

    return artefacts


# ---------------------------------------------------------------------------
# Core metrics
# ---------------------------------------------------------------------------

def compute_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_proba: np.ndarray | None = None,
    class_names: list[str] | None = None,
) -> dict[str, Any]:
    """
    Compute the full suite of classification metrics.

    Parameters
    ----------
    y_true:
        Ground-truth integer labels.
    y_pred:
        Predicted integer labels.
    y_proba:
        Probability estimates ``(n_samples, n_classes)``.  Required for
        AUC-ROC; skipped when ``None``.
    class_names:
        Human-readable class names indexed by label integer.

    Returns
    -------
    Dict with scalar metrics and nested per-class metrics.
    """
    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)
    n_classes = len(np.unique(y_true))
    average = "weighted" if n_classes > 2 else "binary"

    metrics: dict[str, Any] = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision_macro": float(precision_score(y_true, y_pred, average="macro", zero_division=0)),
        "precision_weighted": float(precision_score(y_true, y_pred, average="weighted", zero_division=0)),
        "recall_macro": float(recall_score(y_true, y_pred, average="macro", zero_division=0)),
        "recall_weighted": float(recall_score(y_true, y_pred, average="weighted", zero_division=0)),
        "f1_macro": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        "f1_micro": float(f1_score(y_true, y_pred, average="micro", zero_division=0)),
        "f1_weighted": float(f1_score(y_true, y_pred, average="weighted", zero_division=0)),
    }

    # AUC-ROC
    if y_proba is not None:
        try:
            multiclass = "ovr" if n_classes > 2 else "raise"
            auc_kwargs: dict[str, Any] = {"multi_class": multiclass} if n_classes > 2 else {}
            metrics["auc_roc"] = float(
                roc_auc_score(y_true, y_proba, average="weighted", **auc_kwargs)
            )
        except ValueError as exc:
            logger.warning("Could not compute AUC-ROC: %s", exc)
            metrics["auc_roc"] = None

    # Confusion matrix
    cm = confusion_matrix(y_true, y_pred)
    metrics["confusion_matrix"] = cm.tolist()

    # Per-class metrics
    report = classification_report(
        y_true, y_pred,
        target_names=class_names,
        output_dict=True,
        zero_division=0,
    )
    metrics["per_class"] = {
        k: v for k, v in report.items()
        if k not in ("accuracy", "macro avg", "weighted avg")
    }

    _log_metrics_summary(metrics)
    return metrics


def _log_metrics_summary(metrics: dict[str, Any]) -> None:
    logger.info(
        "Evaluation – accuracy=%.4f  f1_weighted=%.4f  auc_roc=%s",
        metrics["accuracy"],
        metrics["f1_weighted"],
        f"{metrics['auc_roc']:.4f}" if metrics.get("auc_roc") is not None else "N/A",
    )


# ---------------------------------------------------------------------------
# Evaluate a loaded model end-to-end
# ---------------------------------------------------------------------------

def evaluate_model(
    model: Any,
    X_test: np.ndarray,
    y_test: np.ndarray,
    class_names: list[str] | None = None,
) -> dict[str, Any]:
    """
    Generate predictions and compute metrics for *model* on the test split.

    Returns
    -------
    Metrics dict as returned by :func:`compute_metrics`.
    """
    logger.info("Evaluating %s on %d samples", type(model).__name__, len(y_test))
    y_pred = model.predict(X_test)

    y_proba: np.ndarray | None = None
    if hasattr(model, "predict_proba"):
        try:
            y_proba = model.predict_proba(X_test)
        except Exception as exc:
            logger.warning("predict_proba failed: %s", exc)

    return compute_metrics(y_true=y_test, y_pred=y_pred, y_proba=y_proba, class_names=class_names)


# ---------------------------------------------------------------------------
# A/B testing
# ---------------------------------------------------------------------------

def ab_test(
    model_a: Any,
    model_b: Any,
    X_test: np.ndarray,
    y_test: np.ndarray,
    class_names: list[str] | None = None,
    name_a: str = "model_a",
    name_b: str = "model_b",
) -> dict[str, Any]:
    """
    Compare two models on the same test set.

    Returns
    -------
    Dict with keys ``model_a``, ``model_b`` (each containing their metrics
    dicts) and ``comparison`` (which model wins on each metric).
    """
    logger.info("A/B test: %s vs %s", name_a, name_b)
    metrics_a = evaluate_model(model_a, X_test, y_test, class_names)
    metrics_b = evaluate_model(model_b, X_test, y_test, class_names)

    scalar_metrics = [
        "accuracy", "f1_weighted", "f1_macro",
        "precision_weighted", "recall_weighted",
        "auc_roc",
    ]
    comparison: dict[str, Any] = {}
    for m in scalar_metrics:
        val_a = metrics_a.get(m)
        val_b = metrics_b.get(m)
        if val_a is None or val_b is None:
            comparison[m] = {"winner": "N/A", name_a: val_a, name_b: val_b}
            continue
        diff = val_a - val_b
        winner = name_a if diff > 0 else (name_b if diff < 0 else "tie")
        comparison[m] = {
            "winner": winner,
            name_a: round(val_a, 4),
            name_b: round(val_b, 4),
            "delta": round(diff, 4),
        }

    logger.info("A/B comparison complete: %s", json.dumps(
        {m: c["winner"] for m, c in comparison.items()}, indent=2
    ))
    return {
        name_a: metrics_a,
        name_b: metrics_b,
        "comparison": comparison,
    }


# ---------------------------------------------------------------------------
# Confusion matrix plot
# ---------------------------------------------------------------------------

def plot_confusion_matrix(
    cm: list[list[int]],
    class_names: list[str] | None = None,
    output_path: str | Path | None = None,
    title: str = "Confusion Matrix",
) -> Any:
    """
    Render and optionally save a confusion-matrix heatmap.

    Returns
    -------
    Matplotlib :class:`~matplotlib.figure.Figure`, or ``None`` if matplotlib
    is unavailable.
    """
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import seaborn as sns
    except ImportError:
        logger.warning("matplotlib/seaborn not installed; skipping confusion matrix plot")
        return None

    cm_arr = np.array(cm)
    fig, ax = plt.subplots(figsize=(max(8, len(cm_arr)), max(6, len(cm_arr))))
    sns.heatmap(
        cm_arr,
        annot=True,
        fmt="d",
        cmap="Blues",
        xticklabels=class_names or "auto",
        yticklabels=class_names or "auto",
        ax=ax,
    )
    ax.set_title(title)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("True")
    fig.tight_layout()

    if output_path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        fig.savefig(out, dpi=150)
        logger.info("Confusion matrix plot saved to %s", out)

    return fig


# ---------------------------------------------------------------------------
# Report persistence
# ---------------------------------------------------------------------------

def save_evaluation_report(
    report: dict[str, Any],
    output_dir: str | Path = _REPORTS_DIR,
    filename: str = "evaluation_report.json",
) -> Path:
    """
    Write the evaluation *report* dict to *output_dir/<filename>*.

    Returns
    -------
    Path to the written file.
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    out_file = out / filename
    with out_file.open("w") as fh:
        json.dump(report, fh, indent=2, default=str)
    logger.info("Evaluation report saved to %s", out_file)
    return out_file


# ---------------------------------------------------------------------------
# High-level evaluation pipeline
# ---------------------------------------------------------------------------

def run_evaluation(
    X_test: np.ndarray,
    y_test: np.ndarray,
    models_dir: str | Path = _MODELS_DIR,
    reports_dir: str | Path = _REPORTS_DIR,
    class_names: list[str] | None = None,
) -> dict[str, Any]:
    """
    Load all models from *models_dir*, evaluate on the test split, and
    save a combined report.

    Returns
    -------
    Dict mapping model name → metrics dict.
    """
    artefacts = load_evaluation_artefacts(models_dir)
    full_report: dict[str, Any] = {}

    for model_key in ("random_forest", "xgboost"):
        model = artefacts.get(model_key)
        if model is None:
            logger.warning("Model '%s' not found in %s – skipping", model_key, models_dir)
            continue
        metrics = evaluate_model(model, X_test, y_test, class_names)
        full_report[model_key] = metrics

        cm_path = Path(reports_dir) / f"{model_key}_confusion_matrix.png"
        plot_confusion_matrix(metrics["confusion_matrix"], class_names, output_path=cm_path)

    if "random_forest" in full_report and "xgboost" in full_report:
        rf = artefacts["random_forest"]
        xgb = artefacts["xgboost"]
        full_report["ab_test"] = ab_test(
            rf, xgb, X_test, y_test, class_names,
            name_a="random_forest", name_b="xgboost",
        )

    save_evaluation_report(full_report, output_dir=reports_dir)
    return full_report
