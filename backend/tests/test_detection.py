"""
Unit tests for the anomaly detector and risk scorer.
Run with: pytest backend/tests/ -v
"""
from __future__ import annotations

import pytest

from app.detection.anomaly_detector import score_features, AnomalyResult
from app.detection.normalizer import normalize_anomaly_result, NormalizedDetection
from app.correlation.risk_scoring import compute_risk_score, _score_to_severity


# ── Anomaly detector tests ────────────────────────────────────────────────────

def _make_feature_record(**overrides) -> dict:
    base = {
        "feature_schema_version": "1.0",
        "src_ip": "192.0.2.1",
        "window_start": 0,
        "window_end": 30,
        "window_seconds": 30,
        "packet_count": 10,
        "byte_count": 1000,
        "distinct_dst_ports": 5,
        "distinct_dst_ips": 2,
        "connection_attempts": 5,
        "dns_query_count": 0,
        "avg_dns_query_length": 0.0,
        "max_dns_label_entropy": 0.0,
        "unique_dns_subdomains": 0,
    }
    base.update(overrides)
    return base


CUSTOM_THRESHOLDS = {
    "distinct_dst_ports": 20,
    "max_packet_count": 500,
    "dns_query_count": 30,
    "dns_label_entropy": 3.5,
}


def test_benign_traffic_not_flagged():
    """Benign traffic within all thresholds should not be anomalous."""
    records = [_make_feature_record()]
    results = score_features(records, CUSTOM_THRESHOLDS)
    assert len(results) == 1
    result = results[0]
    assert result.is_anomalous is False
    assert result.anomaly_score == 0.0


def test_port_scan_detected():
    """Distinct dst_ports above threshold should trigger anomaly."""
    records = [_make_feature_record(distinct_dst_ports=25)]
    results = score_features(records, CUSTOM_THRESHOLDS)
    result = results[0]
    assert result.is_anomalous is True
    assert any("distinct_dst_ports" in t for t in result.triggered_thresholds)
    assert result.anomaly_score > 0.0


def test_dns_flood_detected():
    """High DNS query count should trigger anomaly."""
    records = [_make_feature_record(dns_query_count=50)]
    results = score_features(records, CUSTOM_THRESHOLDS)
    result = results[0]
    assert result.is_anomalous is True
    assert any("dns_query_count" in t for t in result.triggered_thresholds)


def test_dns_entropy_detected():
    """High DNS label entropy should trigger anomaly."""
    records = [_make_feature_record(max_dns_label_entropy=4.0)]
    results = score_features(records, CUSTOM_THRESHOLDS)
    result = results[0]
    assert result.is_anomalous is True
    assert any("dns_label_entropy" in t for t in result.triggered_thresholds)


def test_score_capped_at_one():
    """Score should never exceed 1.0 even for extreme values."""
    records = [
        _make_feature_record(
            distinct_dst_ports=1000,
            dns_query_count=1000,
            max_dns_label_entropy=10.0,
            packet_count=100000,
        )
    ]
    results = score_features(records, CUSTOM_THRESHOLDS)
    assert results[0].anomaly_score <= 1.0


def test_deterministic_scoring():
    """Same input + same thresholds must produce same score (deterministic)."""
    records = [_make_feature_record(distinct_dst_ports=25, dns_query_count=35)]
    r1 = score_features(records, CUSTOM_THRESHOLDS)[0]
    r2 = score_features(records, CUSTOM_THRESHOLDS)[0]
    assert r1.anomaly_score == r2.anomaly_score


def test_multiple_records():
    """Multiple records should all be independently scored."""
    records = [
        _make_feature_record(src_ip="10.0.0.1", distinct_dst_ports=5),
        _make_feature_record(src_ip="10.0.0.2", distinct_dst_ports=30),
    ]
    results = score_features(records, CUSTOM_THRESHOLDS)
    assert len(results) == 2
    assert results[0].is_anomalous is False
    assert results[1].is_anomalous is True


# ── Risk scorer tests ─────────────────────────────────────────────────────────

def _make_norm_det(detector_type: str, severity: str = "medium", score: float = 0.5):
    return NormalizedDetection(
        detector_type=detector_type,
        detector_name="test",
        event_time=None,
        src_ip="10.0.0.1",
        dst_ip=None,
        src_port=None,
        dst_port=None,
        protocol=None,
        severity=severity,
        score=score,
        rule_id=None,
        rule_version=None,
    )


def test_no_detections_yields_low():
    """No detections should yield a low score."""
    result = compute_risk_score([])
    assert result.risk_score == 0.0
    assert result.severity == "low"


def test_hybrid_corroboration_adds_points():
    """Having both signature and anomaly detections should add corroboration points."""
    sig = _make_norm_det("signature", severity="medium")
    anom = _make_norm_det("anomaly", severity="medium", score=0.5)
    result = compute_risk_score([sig, anom])
    assert result.factors["independent_corroboration"]["has_both"] is True
    assert result.factors["independent_corroboration"]["contribution"] > 0


def test_same_input_same_score():
    """Risk scoring must be deterministic."""
    dets = [_make_norm_det("signature", "high"), _make_norm_det("anomaly", score=0.8)]
    r1 = compute_risk_score(dets)
    r2 = compute_risk_score(dets)
    assert r1.risk_score == r2.risk_score
    assert r1.severity == r2.severity


def test_score_never_exceeds_100():
    """Risk score must be capped at 100."""
    dets = [_make_norm_det("signature", "critical")] * 20 + [
        _make_norm_det("anomaly", score=1.0)
    ] * 10
    result = compute_risk_score(dets)
    assert result.risk_score <= 100.0


def test_severity_bands():
    assert _score_to_severity(80) == "critical"
    assert _score_to_severity(60) == "high"
    assert _score_to_severity(30) == "medium"
    assert _score_to_severity(10) == "low"
