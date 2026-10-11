"""
Output normalizer — converts Snort alert dicts and AnomalyResult objects
into a common NormalizedDetection schema.

Design contract:
- Missing fields use None/unknown — never silently invented.
- normalizer_version is stamped on every record.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.detection.anomaly_detector import AnomalyResult

NORMALIZER_VERSION = "1.0"


@dataclass
class NormalizedDetection:
    """Common detection representation from any detector."""
    detector_type: str              # "signature" | "anomaly"
    detector_name: str
    event_time: str | None
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None
    protocol: str | None
    severity: str | None
    score: float | None
    rule_id: str | None             # stable rule identifier (signature only)
    rule_version: str | None        # rule version string
    feature_snapshot: dict[str, Any] = field(default_factory=dict)
    raw_output_excerpt: str | None = None
    normalizer_version: str = NORMALIZER_VERSION


# ── Snort normalization ───────────────────────────────────────────────────────

_SEVERITY_MAP: dict[int, str] = {
    1: "critical",
    2: "high",
    3: "medium",
    4: "low",
}


def normalize_snort_alert(alert: dict[str, Any]) -> NormalizedDetection:
    """
    Convert a Snort 3 alert_json dict to NormalizedDetection.
    Snort 3 alert_json fields: src_addr, dst_addr, src_port, dst_port,
    proto, timestamp, rule.gid, rule.sid, rule.rev, rule.priority, msg, etc.
    """
    rule_info = alert.get("rule", {}) or {}
    gid = rule_info.get("gid", 1)
    sid = rule_info.get("sid")
    rev = rule_info.get("rev", 0)
    priority = rule_info.get("priority", 3)

    rule_id = f"{gid}:{sid}:{rev}" if sid else None
    severity = _SEVERITY_MAP.get(int(priority), "medium")

    # Bounded raw excerpt (max 500 chars)
    import json as _json
    raw_excerpt = _json.dumps(alert)[:500]

    return NormalizedDetection(
        detector_type="signature",
        detector_name="snort3",
        event_time=alert.get("timestamp"),
        src_ip=alert.get("src_addr"),
        dst_ip=alert.get("dst_addr"),
        src_port=alert.get("src_port"),
        dst_port=alert.get("dst_port"),
        protocol=str(alert.get("proto", "")).upper() or None,
        severity=severity,
        score=None,
        rule_id=rule_id,
        rule_version=str(rev) if rev is not None else None,
        feature_snapshot={},
        raw_output_excerpt=raw_excerpt,
    )


# ── Anomaly normalization ─────────────────────────────────────────────────────

def normalize_anomaly_result(result: AnomalyResult) -> NormalizedDetection:
    """Convert an AnomalyResult to NormalizedDetection."""
    return NormalizedDetection(
        detector_type="anomaly",
        detector_name=result.model_name,
        event_time=str(result.window_start),
        src_ip=result.src_ip,
        dst_ip=None,
        src_port=None,
        dst_port=None,
        protocol=None,
        severity=_anomaly_score_to_severity(result.anomaly_score),
        score=result.anomaly_score,
        rule_id=None,
        rule_version=None,
        feature_snapshot=result.feature_snapshot,
        raw_output_excerpt=f"triggers={result.triggered_thresholds}",
    )


def _anomaly_score_to_severity(score: float) -> str:
    if score >= 0.75:
        return "high"
    if score >= 0.50:
        return "medium"
    if score >= 0.25:
        return "low"
    return "low"
