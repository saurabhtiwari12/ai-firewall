"""
Feature engineering for the AI Firewall Engine.

Transforms raw FlowRecord objects into normalised numpy arrays suitable for
scikit-learn and XGBoost models.

Feature vector (20 dimensions, ordered)
----------------------------------------
 0  duration
 1  packet_count          (log1p)
 2  byte_count            (log1p)
 3  avg_pkt_size
 4  pkt_rate              (log1p)
 5  byte_rate             (log1p)
 6  fwd_packets           (log1p)
 7  bwd_packets           (log1p)
 8  fwd_bwd_ratio
 9  inter_arrival_mean
10  inter_arrival_std
11  syn_count
12  ack_count
13  fin_count
14  rst_count
15  psh_count
16  src_port_norm
17  dst_port_norm
18  protocol_tcp          (1-hot)
19  protocol_udp          (1-hot)

Total: FEATURE_DIM = 20
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass
from typing import Optional, Sequence, Union

import numpy as np

from flow_aggregation import FlowRecord

logger = logging.getLogger(__name__)

FEATURE_DIM = 20
FEATURE_NAMES: list[str] = [
    "duration",
    "packet_count",
    "byte_count",
    "avg_pkt_size",
    "pkt_rate",
    "byte_rate",
    "fwd_packets",
    "bwd_packets",
    "fwd_bwd_ratio",
    "inter_arrival_mean",
    "inter_arrival_std",
    "syn_count",
    "ack_count",
    "fin_count",
    "rst_count",
    "psh_count",
    "src_port_norm",
    "dst_port_norm",
    "protocol_tcp",
    "protocol_udp",
]

_MAX_PORT: float = 65535.0
_PROTOCOL_TCP = 6
_PROTOCOL_UDP = 17


# ---------------------------------------------------------------------------
# Scaler — simple z-score / min-max wrapper that can be persisted via joblib
# ---------------------------------------------------------------------------

@dataclass
class FeatureScaler:
    """
    Lightweight standardisation scaler (z-score).

    Only ``duration``, ``avg_pkt_size``, ``inter_arrival_mean``, and
    ``inter_arrival_std`` are standardised; log-transformed features are
    already on a compact scale.  Port features are already normalised to [0,1].
    One-hot features are left as-is.
    """

    # Indices of features to standardise.
    _STANDARDISE_IDX: tuple[int, ...] = (0, 3, 9, 10)

    mean_: np.ndarray = None  # type: ignore[assignment]
    scale_: np.ndarray = None  # type: ignore[assignment]
    fitted: bool = False

    def fit(self, X: np.ndarray) -> "FeatureScaler":
        """Compute per-feature mean and std from a batch of samples."""
        idx = np.array(self._STANDARDISE_IDX)
        self.mean_ = np.zeros(FEATURE_DIM, dtype=np.float64)
        self.scale_ = np.ones(FEATURE_DIM, dtype=np.float64)
        self.mean_[idx] = X[:, idx].mean(axis=0)
        std = X[:, idx].std(axis=0)
        std[std == 0] = 1.0  # avoid division by zero
        self.scale_[idx] = std
        self.fitted = True
        return self

    def transform(self, X: np.ndarray) -> np.ndarray:
        if not self.fitted:
            return X
        return (X - self.mean_) / self.scale_

    def fit_transform(self, X: np.ndarray) -> np.ndarray:
        return self.fit(X).transform(X)

    def inverse_transform(self, X: np.ndarray) -> np.ndarray:
        if not self.fitted:
            return X
        return X * self.scale_ + self.mean_


# ---------------------------------------------------------------------------
# Core extraction function
# ---------------------------------------------------------------------------

def extract_features(flow: FlowRecord) -> np.ndarray:
    """
    Extract the fixed-length feature vector from a ``FlowRecord``.

    Returns
    -------
    numpy.ndarray
        Shape ``(FEATURE_DIM,)`` with dtype ``float64``.  All values are
        finite (NaN / Inf replaced with 0).
    """
    vec = np.zeros(FEATURE_DIM, dtype=np.float64)

    # -- Raw computed values ------------------------------------------------
    duration = max(flow.duration, 0.0)
    pkt_count = max(flow.packet_count, 0)
    byte_count = max(flow.byte_count, 0)
    avg_pkt = flow.avg_packet_size()
    pkt_rate = flow.pkt_rate()
    byte_rate = flow.byte_rate()
    fwd_pkts = max(flow.fwd_packets, 0)
    bwd_pkts = max(flow.bwd_packets, 0)
    fwd_bwd = flow.fwd_bwd_ratio()
    iat_mean = flow.inter_arrival_mean()
    iat_std = flow.inter_arrival_std()

    # -- Assign -----------------------------------------------------------
    vec[0] = duration
    vec[1] = math.log1p(pkt_count)
    vec[2] = math.log1p(byte_count)
    vec[3] = avg_pkt
    vec[4] = math.log1p(pkt_rate)
    vec[5] = math.log1p(byte_rate)
    vec[6] = math.log1p(fwd_pkts)
    vec[7] = math.log1p(bwd_pkts)
    vec[8] = min(fwd_bwd, 1000.0)           # cap to avoid extreme outliers
    vec[9] = iat_mean
    vec[10] = iat_std
    vec[11] = flow.syn_count
    vec[12] = flow.ack_count
    vec[13] = flow.fin_count
    vec[14] = flow.rst_count
    vec[15] = flow.psh_count
    vec[16] = flow.src_port / _MAX_PORT
    vec[17] = flow.dst_port / _MAX_PORT
    vec[18] = 1.0 if flow.protocol == _PROTOCOL_TCP else 0.0
    vec[19] = 1.0 if flow.protocol == _PROTOCOL_UDP else 0.0

    # -- Sanitise -----------------------------------------------------------
    np.nan_to_num(vec, copy=False, nan=0.0, posinf=0.0, neginf=0.0)
    return vec


def extract_features_batch(
    flows: Sequence[FlowRecord],
) -> np.ndarray:
    """
    Vectorise feature extraction over a sequence of flows.

    Returns
    -------
    numpy.ndarray
        Shape ``(len(flows), FEATURE_DIM)`` with dtype ``float64``.
    """
    if not flows:
        return np.empty((0, FEATURE_DIM), dtype=np.float64)
    return np.vstack([extract_features(f) for f in flows])


# ---------------------------------------------------------------------------
# FeatureEngineer — stateful pipeline
# ---------------------------------------------------------------------------

class FeatureEngineer:
    """
    Stateful feature engineering pipeline.

    Wraps ``extract_features`` with optional scaling.

    Parameters
    ----------
    scaler:
        An already-fitted ``FeatureScaler``.  If ``None``, features are
        returned unscaled.
    """

    def __init__(self, scaler: Optional[FeatureScaler] = None) -> None:
        self.scaler = scaler

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @staticmethod
    def _is_scaler_fitted(scaler: object) -> bool:
        """Return True if *scaler* is fitted, regardless of scaler type.

        Supports both the custom ``FeatureScaler`` (which exposes a ``fitted``
        bool attribute) and sklearn-compatible scalers such as
        ``StandardScaler`` (which set ``n_features_in_`` after ``fit()``).
        """
        if hasattr(scaler, "fitted"):
            return bool(scaler.fitted)  # type: ignore[union-attr]
        # sklearn scalers set n_features_in_ once fit() has been called
        return hasattr(scaler, "n_features_in_")

    def process(self, flow: FlowRecord) -> np.ndarray:
        """Return a 1-D feature vector for a single flow."""
        vec = extract_features(flow)
        if self.scaler and self._is_scaler_fitted(self.scaler):
            vec = self.scaler.transform(vec.reshape(1, -1)).flatten()
        return vec

    def process_batch(self, flows: Sequence[FlowRecord]) -> np.ndarray:
        """Return an (N, FEATURE_DIM) matrix for a list of flows."""
        X = extract_features_batch(flows)
        if self.scaler and self._is_scaler_fitted(self.scaler) and len(X) > 0:
            X = self.scaler.transform(X)
        return X

    def fit_scaler(self, flows: Sequence[FlowRecord]) -> "FeatureEngineer":
        """Fit the internal scaler on a corpus of flows."""
        X = extract_features_batch(flows)
        if len(X) == 0:
            logger.warning("fit_scaler called with empty flows list; scaler not fitted")
            return self
        self.scaler = FeatureScaler()
        self.scaler.fit(X)
        logger.info("FeatureScaler fitted on %d samples", len(X))
        return self

    def save_scaler(self, path: Union[str, "Path"]) -> None:  # type: ignore[name-defined]
        """Persist the fitted scaler using joblib."""
        try:
            import joblib

            joblib.dump(self.scaler, path)
            logger.info("Scaler saved to %s", path)
        except Exception as exc:
            logger.error("Failed to save scaler: %s", exc)

    def load_scaler(self, path: Union[str, "Path"]) -> bool:  # type: ignore[name-defined]
        """Load a previously saved scaler.  Returns True on success."""
        try:
            import joblib

            self.scaler = joblib.load(path)
            logger.info("Scaler loaded from %s", path)
            return True
        except FileNotFoundError:
            logger.warning("Scaler file not found: %s", path)
        except Exception as exc:
            logger.error("Failed to load scaler: %s", exc)
        return False

    @staticmethod
    def feature_names() -> list[str]:
        return list(FEATURE_NAMES)

    @staticmethod
    def feature_dim() -> int:
        return FEATURE_DIM
