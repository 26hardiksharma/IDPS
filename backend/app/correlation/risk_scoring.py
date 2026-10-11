"""
Deterministic risk scorer — computes a reproducible severity score
from documented weighted factors.

Design rules:
- Same detections + same policy version → same score (deterministic).
- LLM may NEVER calculate or override this score.
- All contributing factors are stored alongside the final score.
- Formula and weights are defined here and versioned.

Scoring policy v1.0 (illustrative weights — calibrate against test corpus):
  signature_signal:    0–40 points
  anomaly_band:        0–30 points
  repeated_behavior:   0–20 points
  independent_corroboration: 0–10 points
  Total capped at 100.

Severity bands (configure thresholds after calibration):
  Critical  ≥ 75
  High      ≥ 50
  Medium    ≥ 25
  Low        < 25
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from app.core.logging import get_logger
from app.detection.normalizer import NormalizedDetection

logger = get_logger(__name__)

SCORING_POLICY_VERSION = "1.0"

# ── Scoring parameters (versioned) ────────────────────────────────────────────

SCORING_WEIGHTS = {
    "signature_max": 40,
    "anomaly_max": 30,
    "repeated_max": 20,
    "corroboration_max": 10,
}

SEVERITY_THRESHOLDS = {
    "critical": 75,
    "high": 50,
    "medium": 25,
}

SCORING_CONFIG = {
    "version": SCORING_POLICY_VERSION,
    "weights": SCORING_WEIGHTS,
    "severity_thresholds": SEVERITY_THRESHOLDS,
}


@dataclass
class RiskDecision:
    risk_score: float
    severity: str
    factors: dict[str, Any]
    policy_version: str


def compute_risk_score(
    detections: list[NormalizedDetection],
    policy_version: str = SCORING_POLICY_VERSION,
) -> RiskDecision:
    """
    Compute deterministic risk score from a list of normalized detections.
    Returns RiskDecision with score, severity band, and all factor values.
    """
    factors: dict[str, Any] = {}

    # ── Factor 1: Signature signal ────────────────────────────────────────────
    sig_dets = [d for d in detections if d.detector_type == "signature"]
    sig_max_sev = _max_severity_score(sig_dets)
    # Scale 0-40 based on severity and count
    sig_score = min(sig_max_sev + len(sig_dets) * 2, SCORING_WEIGHTS["signature_max"])
    factors["signature_signal"] = {
        "count": len(sig_dets),
        "max_severity": _max_severity_label(sig_dets),
        "raw_severity_score": sig_max_sev,
        "contribution": round(sig_score, 2),
    }

    # ── Factor 2: Anomaly band ────────────────────────────────────────────────
    anom_dets = [d for d in detections if d.detector_type == "anomaly"]
    max_anomaly_score = max((d.score or 0.0 for d in anom_dets), default=0.0)
    anomaly_contribution = round(max_anomaly_score * SCORING_WEIGHTS["anomaly_max"], 2)
    factors["anomaly_band"] = {
        "count": len(anom_dets),
        "max_score": round(max_anomaly_score, 4),
        "contribution": anomaly_contribution,
    }

    # ── Factor 3: Repeated behavior ───────────────────────────────────────────
    # Measured by total detection count relative to a threshold
    total = len(detections)
    repeat_factor = min(total / 5.0, 1.0)  # saturates at 5 detections
    repeat_contribution = round(repeat_factor * SCORING_WEIGHTS["repeated_max"], 2)
    factors["repeated_behavior"] = {
        "total_detections": total,
        "contribution": repeat_contribution,
    }

    # ── Factor 4: Independent corroboration ───────────────────────────────────
    detector_types = {d.detector_type for d in detections}
    has_both = "signature" in detector_types and "anomaly" in detector_types
    corroboration_contribution = (
        float(SCORING_WEIGHTS["corroboration_max"]) if has_both else 0.0
    )
    factors["independent_corroboration"] = {
        "detector_types": sorted(detector_types),
        "has_both": has_both,
        "contribution": corroboration_contribution,
    }

    # ── Final score ───────────────────────────────────────────────────────────
    raw_total = sig_score + anomaly_contribution + repeat_contribution + corroboration_contribution
    risk_score = round(min(raw_total, 100.0), 2)
    severity = _score_to_severity(risk_score)
    factors["total_raw"] = round(raw_total, 2)
    factors["risk_score"] = risk_score
    factors["severity"] = severity

    logger.info(
        "risk_score_computed",
        risk_score=risk_score,
        severity=severity,
        policy_version=policy_version,
    )

    return RiskDecision(
        risk_score=risk_score,
        severity=severity,
        factors=factors,
        policy_version=policy_version,
    )


def _max_severity_score(dets: list[NormalizedDetection]) -> float:
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    scores = [order.get(d.severity or "low", 1) for d in dets]
    if not scores:
        return 0.0
    # Map back: critical=30, high=20, medium=10, low=5
    mapping = {4: 30.0, 3: 20.0, 2: 10.0, 1: 5.0}
    return mapping.get(max(scores), 0.0)


def _max_severity_label(dets: list[NormalizedDetection]) -> str:
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    if not dets:
        return "none"
    best = max(dets, key=lambda d: order.get(d.severity or "low", 1))
    return best.severity or "low"


def _score_to_severity(score: float) -> str:
    if score >= SEVERITY_THRESHOLDS["critical"]:
        return "critical"
    if score >= SEVERITY_THRESHOLDS["high"]:
        return "high"
    if score >= SEVERITY_THRESHOLDS["medium"]:
        return "medium"
    return "low"


def get_scoring_config() -> dict[str, Any]:
    """Return the current scoring config dict for versioning purposes."""
    return SCORING_CONFIG.copy()
