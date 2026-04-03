"""
Composite threat scoring module.

Combines AI detection, anomaly, and behavioral scores into a single
weighted threat score and maps it to a risk classification.

Weights
-------
  AI (RF/XGB confidence)  50 %
  Anomaly (IsolationForest) 30 %
  Behavioral              20 %

Risk bands
----------
  Safe       [0.00, 0.30)
  Suspicious [0.30, 0.60)
  High Risk  [0.60, 0.80)
  Critical   [0.80, 1.00]
"""

from __future__ import annotations

import collections
import logging
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from ai_detection import DetectionResult, AttackType
from behavioral_analysis import BehavioralScore

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Risk classification
# ---------------------------------------------------------------------------

class RiskLevel(str, Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    HIGH_RISK = "high_risk"
    CRITICAL = "critical"


# ---------------------------------------------------------------------------
# Composite score
# ---------------------------------------------------------------------------

@dataclass
class ThreatScore:
    """Fully-resolved threat assessment for a single flow."""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int

    # Component scores [0, 1]
    ai_score: float = 0.0
    anomaly_score: float = 0.0
    behavioral_score: float = 0.0

    # Weighted composite [0, 1]
    composite: float = 0.0

    risk_level: RiskLevel = RiskLevel.SAFE
    attack_type: AttackType = AttackType.BENIGN

    # Flags from behavioral analysis
    behavioral_indicators: list[str] = field(default_factory=list)

    # Metadata
    timestamp: float = field(default_factory=time.time)
    model_versions: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "ai_score": round(self.ai_score, 4),
            "anomaly_score": round(self.anomaly_score, 4),
            "behavioral_score": round(self.behavioral_score, 4),
            "composite": round(self.composite, 4),
            "risk_level": self.risk_level.value,
            "attack_type": self.attack_type.value,
            "behavioral_indicators": self.behavioral_indicators,
            "timestamp": self.timestamp,
            "model_versions": self.model_versions,
        }


# ---------------------------------------------------------------------------
# ThreatScorer
# ---------------------------------------------------------------------------

class ThreatScorer:
    """
    Weighted combination of AI, anomaly, and behavioral sub-scores.

    Parameters
    ----------
    ai_weight / anomaly_weight / behavioral_weight:
        Must sum to 1.0.
    safe_threshold / suspicious_threshold / high_risk_threshold:
        Composite score boundaries for risk classification.
    history_size:
        Number of recent ``ThreatScore`` objects retained in memory.
    """

    def __init__(
        self,
        ai_weight: float = 0.50,
        anomaly_weight: float = 0.30,
        behavioral_weight: float = 0.20,
        safe_threshold: float = 0.30,
        suspicious_threshold: float = 0.60,
        high_risk_threshold: float = 0.80,
        history_size: int = 1_000,
    ) -> None:
        if abs(ai_weight + anomaly_weight + behavioral_weight - 1.0) > 1e-6:
            raise ValueError("Weights must sum to 1.0")

        self.ai_weight = ai_weight
        self.anomaly_weight = anomaly_weight
        self.behavioral_weight = behavioral_weight
        self.safe_threshold = safe_threshold
        self.suspicious_threshold = suspicious_threshold
        self.high_risk_threshold = high_risk_threshold
        self.history_size = history_size

        self._history: collections.deque[ThreatScore] = collections.deque(
            maxlen=history_size
        )
        self._history_lock = threading.Lock()

        # Simple counters per risk level
        self._counters: dict[RiskLevel, int] = {lvl: 0 for lvl in RiskLevel}
        self._total_scored = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def score(
        self,
        ai_result: DetectionResult,
        behavioral_result: BehavioralScore,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: int,
    ) -> ThreatScore:
        """
        Compute the composite threat score.

        Parameters
        ----------
        ai_result:
            Output from ``AIDetector.predict``.
        behavioral_result:
            Output from ``BehavioralAnalyzer.analyze``.
        src_ip / dst_ip / src_port / dst_port / protocol:
            Flow identity for the returned ``ThreatScore``.

        Returns
        -------
        ThreatScore
        """
        ai_score = float(ai_result.confidence)
        anomaly_score = float(ai_result.anomaly_score)
        behavioral_score = float(behavioral_result.overall)

        composite = (
            self.ai_weight * ai_score
            + self.anomaly_weight * anomaly_score
            + self.behavioral_weight * behavioral_score
        )
        composite = max(0.0, min(1.0, composite))

        risk_level = self._classify(composite)

        ts = ThreatScore(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            ai_score=ai_score,
            anomaly_score=anomaly_score,
            behavioral_score=behavioral_score,
            composite=composite,
            risk_level=risk_level,
            attack_type=ai_result.attack_type,
            behavioral_indicators=list(behavioral_result.indicators),
            model_versions=dict(ai_result.model_versions),
        )

        with self._history_lock:
            self._history.append(ts)
            self._counters[risk_level] += 1
            self._total_scored += 1

        if risk_level in (RiskLevel.HIGH_RISK, RiskLevel.CRITICAL):
            logger.warning(
                "THREAT [%s] src=%s dst=%s:%d composite=%.3f type=%s indicators=%s",
                risk_level.value,
                src_ip,
                dst_ip,
                dst_port,
                composite,
                ai_result.attack_type.value,
                behavioral_result.indicators,
            )
        else:
            logger.debug(
                "Scored flow %s -> %s:%d composite=%.3f risk=%s",
                src_ip,
                dst_ip,
                dst_port,
                composite,
                risk_level.value,
            )

        return ts

    def get_recent(self, n: int = 100) -> list[ThreatScore]:
        """Return up to *n* most-recently scored flows."""
        with self._history_lock:
            data = list(self._history)
        return data[-n:]

    def get_statistics(self) -> dict:
        """Return aggregate scoring statistics."""
        with self._history_lock:
            return {
                "total_scored": self._total_scored,
                "by_risk": {lvl.value: cnt for lvl, cnt in self._counters.items()},
                "history_length": len(self._history),
            }

    def get_ip_risk(self, ip: str, window_sec: float = 300.0) -> Optional[float]:
        """
        Return the maximum composite score seen for *ip* in the last *window_sec*.

        Returns ``None`` if no history exists for the IP.
        """
        cutoff = time.time() - window_sec
        with self._history_lock:
            scores = [
                ts.composite
                for ts in self._history
                if ts.src_ip == ip and ts.timestamp >= cutoff
            ]
        return max(scores) if scores else None

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _classify(self, composite: float) -> RiskLevel:
        if composite >= self.high_risk_threshold:
            return RiskLevel.CRITICAL
        if composite >= self.suspicious_threshold:
            return RiskLevel.HIGH_RISK
        if composite >= self.safe_threshold:
            return RiskLevel.SUSPICIOUS
        return RiskLevel.SAFE
