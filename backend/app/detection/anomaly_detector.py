"""
Anomaly detector — applies transparent threshold-based detection over
extracted flow features. Optionally compares with Isolation Forest (P1).

Design contract:
- Thresholds are defined in a versioned config (from Settings or policy file).
- Score is deterministic: same features + same thresholds → same score.
- High anomaly score ≠ proof of malicious activity; it indicates deviation.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)

MODEL_NAME = "threshold_baseline"
MODEL_VERSION = "1.0"
FEATURE_SCHEMA_VERSION = "1.0"


@dataclass
class AnomalyResult:
    """Result of anomaly scoring for one feature record."""
    src_ip: str
    window_start: int
    window_end: int
    anomaly_score: float          # 0.0–1.0
    is_anomalous: bool
    triggered_thresholds: list[str]
    feature_snapshot: dict[str, Any]
    model_name: str
    model_version: str
    feature_schema_version: str


def score_features(
    feature_records: list[dict[str, Any]],
    threshold_config: dict[str, Any] | None = None,
) -> list[AnomalyResult]:
    """
    Score each feature record against documented thresholds.
    Returns one AnomalyResult per input record.
    """
    settings = get_settings()
    config = threshold_config or _default_thresholds(settings)

    results: list[AnomalyResult] = []
    for rec in feature_records:
        result = _score_one(rec, config)
        results.append(result)
        if result.is_anomalous:
            logger.info(
                "anomaly_detected",
                src_ip=result.src_ip,
                score=result.anomaly_score,
                triggers=result.triggered_thresholds,
            )
    return results


def _score_one(
    rec: dict[str, Any],
    config: dict[str, Any],
) -> AnomalyResult:
    """
    Apply threshold rules to a single feature record.
    Each triggered threshold contributes a fractional score component.
    Score is capped at 1.0.
    """
    triggers: list[str] = []
    score_parts: list[float] = []

    # Port scan indicator
    max_ports: int = config.get("distinct_dst_ports", 20)
    if rec.get("distinct_dst_ports", 0) >= max_ports:
        triggers.append(f"distinct_dst_ports>={max_ports}")
        ratio = min(rec["distinct_dst_ports"] / max(max_ports, 1), 3.0) / 3.0
        score_parts.append(0.40 * min(ratio, 1.0))

    # Packet rate (packets per window)
    max_pkt: float = config.get("max_packet_count", 500)
    if rec.get("packet_count", 0) >= max_pkt:
        triggers.append(f"packet_count>={max_pkt}")
        ratio = min(rec["packet_count"] / max(max_pkt, 1), 3.0) / 3.0
        score_parts.append(0.20 * min(ratio, 1.0))

    # DNS query rate
    max_dns: int = config.get("dns_query_count", 30)
    if rec.get("dns_query_count", 0) >= max_dns:
        triggers.append(f"dns_query_count>={max_dns}")
        ratio = min(rec["dns_query_count"] / max(max_dns, 1), 3.0) / 3.0
        score_parts.append(0.25 * min(ratio, 1.0))

    # DNS label entropy
    max_entropy: float = config.get("dns_label_entropy", 3.5)
    if rec.get("max_dns_label_entropy", 0.0) >= max_entropy:
        triggers.append(f"dns_label_entropy>={max_entropy}")
        ratio = min(rec["max_dns_label_entropy"] / max(max_entropy, 0.01), 3.0) / 3.0
        score_parts.append(0.15 * min(ratio, 1.0))

    anomaly_score = round(min(sum(score_parts), 1.0), 4)
    is_anomalous = bool(triggers)

    return AnomalyResult(
        src_ip=rec.get("src_ip", "unknown"),
        window_start=rec.get("window_start", 0),
        window_end=rec.get("window_end", 0),
        anomaly_score=anomaly_score,
        is_anomalous=is_anomalous,
        triggered_thresholds=triggers,
        feature_snapshot=rec,
        model_name=MODEL_NAME,
        model_version=MODEL_VERSION,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
    )


def _default_thresholds(settings: Any) -> dict[str, Any]:
    return {
        "distinct_dst_ports": settings.ANOMALY_THRESHOLD_DISTINCT_PORTS,
        "max_packet_count": settings.ANOMALY_THRESHOLD_PKT_RATE,
        "dns_query_count": settings.ANOMALY_THRESHOLD_DNS_QUERIES,
        "dns_label_entropy": settings.ANOMALY_THRESHOLD_DNS_ENTROPY,
    }


def threshold_config_dict(settings: Any | None = None) -> dict[str, Any]:
    """Return the current threshold config as a plain dict (for versioning)."""
    s = settings or get_settings()
    return _default_thresholds(s)
