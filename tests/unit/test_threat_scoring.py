"""Unit tests for the threat_scoring module."""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../firewall-engine'))

import pytest
from unittest.mock import MagicMock
from threat_scoring import ThreatScorer, RiskLevel, CompositeScore
from ai_detection import DetectionResult, AttackType
from behavioral_analysis import BehavioralScore


def _make_detection(confidence: float, is_attack: bool = True) -> DetectionResult:
    return DetectionResult(
        is_attack=is_attack,
        confidence=confidence,
        attack_type=AttackType.DOS if is_attack else AttackType.NORMAL,
        model_scores={"rf": confidence, "xgb": confidence},
    )


def _make_behavioral(score: float) -> BehavioralScore:
    bs = BehavioralScore()
    bs.port_scan_score = score
    return bs


def test_composite_score_calculation():
    scorer = ThreatScorer()
    det = _make_detection(0.8)
    beh = _make_behavioral(0.5)
    anomaly = 0.6
    result: CompositeScore = scorer.score(det, anomaly, beh)
    assert 0.0 <= result.composite <= 1.0


def test_risk_classification_safe():
    scorer = ThreatScorer()
    det = _make_detection(0.0, is_attack=False)
    beh = _make_behavioral(0.0)
    result = scorer.score(det, 0.0, beh)
    assert result.risk_level == RiskLevel.SAFE


def test_risk_classification_critical():
    scorer = ThreatScorer()
    det = _make_detection(1.0)
    beh = _make_behavioral(1.0)
    result = scorer.score(det, 1.0, beh)
    assert result.risk_level == RiskLevel.CRITICAL


def test_score_history_tracking():
    scorer = ThreatScorer()
    det = _make_detection(0.5)
    beh = _make_behavioral(0.3)
    for _ in range(5):
        scorer.score(det, 0.4, beh)
    history = scorer.get_history()
    assert len(history) >= 5


def test_weighted_scoring():
    scorer = ThreatScorer()
    # High AI score should drive composite toward high end
    det_high = _make_detection(1.0)
    beh_low = _make_behavioral(0.0)
    result_high = scorer.score(det_high, 0.0, beh_low)

    det_low = _make_detection(0.0, is_attack=False)
    result_low = scorer.score(det_low, 0.0, beh_low)

    assert result_high.composite > result_low.composite
