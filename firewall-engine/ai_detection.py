"""
AI-driven threat detection module.

Supports three model types:
  * **Random Forest** – supervised multi-class classifier (attack type)
  * **Isolation Forest** – unsupervised anomaly detection (novelty score)
  * **XGBoost** – gradient-boosted ensemble classifier (highest precision)

All models are loaded lazily from the ``models/`` directory.  When a trained
model file is absent, a deterministic *mock* model is substituted so the
pipeline remains functional in development/CI environments.

Async prediction is provided via a ``ThreadPoolExecutor``-backed wrapper that
returns a ``concurrent.futures.Future``.
"""

from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional, Union

import numpy as np

from feature_engineering import FEATURE_DIM

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Attack categories
# ---------------------------------------------------------------------------

class AttackType(str, Enum):
    BENIGN = "benign"
    PORT_SCAN = "port_scan"
    BRUTE_FORCE = "brute_force"
    DOS = "dos"
    DDOS = "ddos"
    DATA_EXFIL = "data_exfiltration"
    BOTNET = "botnet"
    EXPLOIT = "exploit"
    UNKNOWN = "unknown"


_LABEL_MAP: dict[int, AttackType] = {
    0: AttackType.BENIGN,
    1: AttackType.PORT_SCAN,
    2: AttackType.BRUTE_FORCE,
    3: AttackType.DOS,
    4: AttackType.DDOS,
    5: AttackType.DATA_EXFIL,
    6: AttackType.BOTNET,
    7: AttackType.EXPLOIT,
}


# ---------------------------------------------------------------------------
# Prediction result
# ---------------------------------------------------------------------------

@dataclass
class DetectionResult:
    """Aggregated output from all three models for a single feature vector."""

    # Supervised classifier output
    attack_type: AttackType = AttackType.UNKNOWN
    rf_confidence: float = 0.0      # Random Forest: P(predicted_class)
    xgb_confidence: float = 0.0     # XGBoost: P(predicted_class)

    # Isolation Forest: scaled anomaly score in [0, 1] (higher = more anomalous)
    anomaly_score: float = 0.0

    # Combined confidence [0, 1]
    confidence: float = 0.0

    # Model version tags
    model_versions: dict[str, str] = field(default_factory=dict)

    # Latency
    inference_ms: float = 0.0


# ---------------------------------------------------------------------------
# Mock models for environments without trained artifacts
# ---------------------------------------------------------------------------

class _MockRFClassifier:
    """Deterministic stand-in for a scikit-learn RandomForestClassifier."""

    version = "mock-rf-1.0"
    classes_ = np.arange(len(_LABEL_MAP))

    def predict(self, X: np.ndarray) -> np.ndarray:
        # Heuristic: use packet_count feature (index 1) to decide
        labels = np.where(X[:, 1] > 4.0, 3, 0)
        return labels.astype(int)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        n = len(X)
        proba = np.zeros((n, len(_LABEL_MAP)), dtype=np.float64)
        labels = self.predict(X)
        for i, lbl in enumerate(labels):
            proba[i, lbl] = 0.75
            proba[i, :] += 0.25 / len(_LABEL_MAP)
            proba[i] /= proba[i].sum()
        return proba


class _MockIsolationForest:
    """Deterministic stand-in for a scikit-learn IsolationForest."""

    version = "mock-iforest-1.0"

    def decision_function(self, X: np.ndarray) -> np.ndarray:
        # Larger byte_count → more anomalous (negative scores)
        scores = -X[:, 2] / 15.0 + 0.3
        return np.clip(scores, -1.0, 1.0)

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        return self.decision_function(X)


class _MockXGBClassifier:
    """Deterministic stand-in for an XGBoost classifier."""

    version = "mock-xgb-1.0"
    classes_ = np.arange(len(_LABEL_MAP))

    def predict(self, X: np.ndarray) -> np.ndarray:
        labels = np.where(X[:, 14] > 2, 2, 0)  # rst_count heuristic
        return labels.astype(int)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        n = len(X)
        proba = np.zeros((n, len(_LABEL_MAP)), dtype=np.float64)
        labels = self.predict(X)
        for i, lbl in enumerate(labels):
            proba[i, lbl] = 0.80
            proba[i, :] += 0.20 / len(_LABEL_MAP)
            proba[i] /= proba[i].sum()
        return proba


# ---------------------------------------------------------------------------
# AIDetector
# ---------------------------------------------------------------------------

class AIDetector:
    """
    Loads and runs Random Forest, Isolation Forest, and XGBoost models.

    Parameters
    ----------
    models_dir:
        Directory containing ``*.joblib`` model files.
    rf_filename / if_filename / xgb_filename:
        File names within *models_dir*.
    async_workers:
        Thread-pool size for asynchronous inference.
    """

    def __init__(
        self,
        models_dir: Union[str, Path] = "models",
        rf_filename: str = "random_forest.joblib",
        if_filename: str = "isolation_forest.joblib",
        xgb_filename: str = "xgboost_model.joblib",
        async_workers: int = 2,
    ) -> None:
        self.models_dir = Path(models_dir)
        self.rf_filename = rf_filename
        self.if_filename = if_filename
        self.xgb_filename = xgb_filename

        self._rf: Optional[object] = None
        self._iforest: Optional[object] = None
        self._xgb: Optional[object] = None

        self._rf_version = "not-loaded"
        self._iforest_version = "not-loaded"
        self._xgb_version = "not-loaded"

        self._load_lock = threading.Lock()
        self._loaded = False

        self._executor = ThreadPoolExecutor(
            max_workers=async_workers, thread_name_prefix="ai-detect"
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def load_models(self) -> None:
        """Load all models from disk (or fall back to mocks)."""
        with self._load_lock:
            if self._loaded:
                return
            self._rf = self._load_or_mock(
                self.rf_filename, _MockRFClassifier(), "random_forest"
            )
            self._iforest = self._load_or_mock(
                self.if_filename, _MockIsolationForest(), "isolation_forest"
            )
            self._xgb = self._load_or_mock(
                self.xgb_filename, _MockXGBClassifier(), "xgboost"
            )
            self._loaded = True
            logger.info(
                "AI models ready: RF=%s IF=%s XGB=%s",
                self._rf_version,
                self._iforest_version,
                self._xgb_version,
            )

    def shutdown(self) -> None:
        """Shut down the thread-pool executor."""
        self._executor.shutdown(wait=True, cancel_futures=False)

    # ------------------------------------------------------------------
    # Synchronous prediction
    # ------------------------------------------------------------------

    def predict(self, features: np.ndarray) -> DetectionResult:
        """
        Run all three models on a 1-D feature vector.

        Parameters
        ----------
        features:
            Shape ``(FEATURE_DIM,)`` numpy array (unscaled or pre-scaled,
            consistent with how models were trained).

        Returns
        -------
        DetectionResult
        """
        if not self._loaded:
            self.load_models()

        start = time.perf_counter()
        X = features.reshape(1, -1)

        result = DetectionResult(
            model_versions={
                "random_forest": self._rf_version,
                "isolation_forest": self._iforest_version,
                "xgboost": self._xgb_version,
            }
        )

        # --- Random Forest --------------------------------------------------
        try:
            rf_label, rf_conf = self._classify(self._rf, X)
            result.attack_type = _LABEL_MAP.get(rf_label, AttackType.UNKNOWN)
            result.rf_confidence = rf_conf
        except Exception as exc:
            logger.warning("RF prediction failed: %s", exc)

        # --- Isolation Forest -----------------------------------------------
        try:
            result.anomaly_score = self._anomaly_score(self._iforest, X)
        except Exception as exc:
            logger.warning("IsolationForest prediction failed: %s", exc)

        # --- XGBoost --------------------------------------------------------
        try:
            xgb_label, xgb_conf = self._classify(self._xgb, X)
            result.xgb_confidence = xgb_conf
            # If XGB disagrees with RF and is more confident, defer to XGB
            if xgb_conf > result.rf_confidence and xgb_label != 0:
                result.attack_type = _LABEL_MAP.get(xgb_label, AttackType.UNKNOWN)
        except Exception as exc:
            logger.warning("XGBoost prediction failed: %s", exc)

        # --- Composite confidence -------------------------------------------
        # Weighted blend: RF 40%, XGB 40%, anomaly 20%
        result.confidence = (
            0.40 * result.rf_confidence
            + 0.40 * result.xgb_confidence
            + 0.20 * result.anomaly_score
        )
        result.confidence = float(np.clip(result.confidence, 0.0, 1.0))

        result.inference_ms = (time.perf_counter() - start) * 1000
        return result

    def predict_batch(self, features: np.ndarray) -> list[DetectionResult]:
        """
        Predict over a batch of feature vectors.

        Parameters
        ----------
        features:
            Shape ``(N, FEATURE_DIM)`` numpy array.
        """
        if not self._loaded:
            self.load_models()
        return [self.predict(features[i]) for i in range(len(features))]

    # ------------------------------------------------------------------
    # Asynchronous prediction
    # ------------------------------------------------------------------

    def predict_async(self, features: np.ndarray) -> Future:
        """
        Submit a prediction to the thread pool.

        Returns
        -------
        concurrent.futures.Future[DetectionResult]
        """
        return self._executor.submit(self.predict, features)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_or_mock(self, filename: str, mock: object, kind: str) -> object:
        path = self.models_dir / filename
        try:
            import joblib

            model = joblib.load(path)
            version = getattr(model, "version", f"{kind}-loaded")
            setattr(self, f"_{kind.replace('-', '_')}_version", version)
            logger.info("Loaded %s from %s (version=%s)", kind, path, version)
            return model
        except FileNotFoundError:
            logger.warning(
                "Model file '%s' not found – using mock %s", path, kind
            )
        except Exception as exc:
            logger.warning("Failed to load %s (%s) – using mock", kind, exc)

        version = getattr(mock, "version", f"mock-{kind}")
        attr = f"_{kind.replace('-', '_')}_version"
        # Map compound attribute name to instance attr
        if kind == "random_forest":
            self._rf_version = version
        elif kind == "isolation_forest":
            self._iforest_version = version
        elif kind == "xgboost":
            self._xgb_version = version
        return mock

    @staticmethod
    def _classify(model: object, X: np.ndarray) -> tuple[int, float]:
        """Return (predicted_label, confidence) from a classifier."""
        proba: np.ndarray = model.predict_proba(X)[0]  # type: ignore[attr-defined]
        label = int(np.argmax(proba))
        conf = float(proba[label])
        return label, conf

    @staticmethod
    def _anomaly_score(model: object, X: np.ndarray) -> float:
        """
        Map Isolation Forest decision_function output to [0, 1].

        Scores from IsolationForest range roughly (-0.5, 0.5).
        Negative values indicate anomalies; we invert and normalise.
        """
        raw: float = float(model.decision_function(X)[0])  # type: ignore[attr-defined]
        # Map (-inf, +inf) → [0, 1] with sigmoid-like rescaling
        # decision_function returns ~0 for inliers, negative for outliers.
        score = 1.0 / (1.0 + np.exp(5.0 * raw))
        return float(np.clip(score, 0.0, 1.0))
