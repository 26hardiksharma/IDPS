"""
Comprehensive validation and regression test suite for XAI-IDPS detection pipeline:
  1. Snort 3 invocation safety, error handling, and JSON parsing.
  2. Normalization consistency and missing field tolerance.
  3. Anomaly detection robustness (NaN, Inf, None, missing keys).
  4. Incident correlation sliding window and entity grouping.
  5. Deterministic risk scoring repeatability and factor preservation.
  6. Run lifecycle state machine transitions and conflict detection.
  7. Test PCAP fixture integrity and validation.
"""
from __future__ import annotations

import json
from pathlib import Path
import pytest
from unittest.mock import AsyncMock, patch

from app.core.errors import ConflictError, SnortError, InputRejectedError
from app.db.models import RunStatus
from app.detection.anomaly_detector import score_features, _score_one
from app.detection.normalizer import normalize_snort_alert, normalize_anomaly_result, NormalizedDetection
from app.detection.snort_runner import _build_snort_args, _parse_snort_output
from app.correlation.incident_builder import correlate_detections
from app.correlation.risk_scoring import compute_risk_score, _score_to_severity
from app.orchestration.run_state import assert_transition, can_transition
from app.provenance.hashing import hash_file


# ── 1. Snort 3 Integration & Safety ──────────────────────────────────────────

def test_snort_safe_args_construction(tmp_path: Path):
    """Snort arguments must be a clean list without shell interpolation."""
    pcap = tmp_path / "test.pcap"
    pcap.touch()
    cfg = tmp_path / "snort.lua"
    cfg.touch()
    out = tmp_path / "output"

    args = _build_snort_args(pcap_path=pcap, config_path=cfg, output_dir=out)
    assert isinstance(args, list)
    assert "-r" in args
    assert str(pcap) in args
    assert "-c" in args
    assert str(cfg) in args
    assert "-l" in args
    assert str(out) in args
    assert "-A" in args
    assert "json" in args


def test_snort_parse_valid_alert_json(tmp_path: Path):
    """Parser must correctly extract Snort 3 JSON alert objects."""
    out_dir = tmp_path / "snort_out"
    out_dir.mkdir()
    alert_file = out_dir / "alert_json.txt"

    sample_alert = {
        "timestamp": "01/15-10:20:30.123456",
        "src_addr": "192.168.1.100",
        "dst_addr": "192.168.1.1",
        "src_port": 54321,
        "dst_port": 80,
        "proto": "TCP",
        "rule": {
            "gid": 1,
            "sid": 20001,
            "rev": 2,
            "priority": 1,
            "msg": "INDICATOR-SCAN SYN scan detected",
        },
    }
    alert_file.write_text(json.dumps(sample_alert) + "\n")

    alerts = _parse_snort_output(out_dir, stdout_text="")
    assert len(alerts) == 1
    assert alerts[0]["src_addr"] == "192.168.1.100"
    assert alerts[0]["rule"]["sid"] == 20001


def test_snort_parse_malformed_json_graceful(tmp_path: Path):
    """Malformed or partial lines in alert output must not crash parser."""
    out_dir = tmp_path / "snort_out"
    out_dir.mkdir()
    alert_file = out_dir / "alert_json.txt"
    alert_file.write_text("NOT_JSON\n{\"valid\": 1}\n{truncated json...\n")

    alerts = _parse_snort_output(out_dir, stdout_text="")
    assert len(alerts) == 1
    assert alerts[0]["valid"] == 1


# ── 2. Detection Normalization ────────────────────────────────────────────────

def test_normalize_snort_alert_fields():
    """Verify Snort alert normalization mappings and bounding."""
    raw = {
        "timestamp": "1700000000.123",
        "src_addr": "10.0.0.5",
        "dst_addr": "10.0.0.1",
        "src_port": 40000,
        "dst_port": 22,
        "proto": "tcp",
        "rule": {"gid": 1, "sid": 10001, "rev": 3, "priority": 1},
    }
    norm = normalize_snort_alert(raw)
    assert norm.detector_type == "signature"
    assert norm.detector_name == "snort3"
    assert norm.rule_id == "1:10001:3"
    assert norm.rule_version == "3"
    assert norm.severity == "critical"  # priority 1 -> critical
    assert norm.src_ip == "10.0.0.5"
    assert norm.dst_ip == "10.0.0.1"
    assert norm.src_port == 40000
    assert norm.dst_port == 22
    assert norm.protocol == "TCP"
    assert len(norm.raw_output_excerpt) <= 500


def test_normalize_snort_alert_missing_fields():
    """Missing or non-integer fields in alert dict must normalize cleanly."""
    raw = {
        "rule": {"priority": "invalid", "sid": None},
        "src_port": "not-a-port",
    }
    norm = normalize_snort_alert(raw)
    assert norm.rule_id is None
    assert norm.severity == "medium"
    assert norm.src_port is None


# ── 3. Anomaly Detector Robustness ───────────────────────────────────────────

def test_anomaly_detector_nan_inf_none_resilience():
    """Non-finite, NaN, and None values must be handled deliberately without exceptions."""
    malformed_record = {
        "src_ip": "192.168.1.99",
        "window_start": None,
        "window_end": float("nan"),
        "distinct_dst_ports": None,
        "packet_count": float("inf"),
        "dns_query_count": "invalid_string",
        "max_dns_label_entropy": float("nan"),
    }
    config = {
        "distinct_dst_ports": 20,
        "max_packet_count": 500,
        "dns_query_count": 30,
        "dns_label_entropy": 3.5,
    }
    results = score_features([malformed_record], config)
    assert len(results) == 1
    res = results[0]
    assert 0.0 <= res.anomaly_score <= 1.0
    assert res.src_ip == "192.168.1.99"


def test_anomaly_detector_empty_input():
    """Scoring an empty list returns an empty list."""
    results = score_features([], {})
    assert results == []


# ── 4. Incident Correlation Engine ───────────────────────────────────────────

def test_correlation_sliding_window():
    """Detections beyond time window must split into separate incident groups."""
    d1 = NormalizedDetection(
        detector_type="anomaly",
        detector_name="threshold",
        event_time="1000.0",
        src_ip="192.168.1.50",
        dst_ip=None,
        src_port=None,
        dst_port=None,
        protocol=None,
        severity="medium",
        score=0.4,
        rule_id=None,
        rule_version=None,
    )
    d2 = NormalizedDetection(
        detector_type="anomaly",
        detector_name="threshold",
        event_time="1050.0",  # within 300s window
        src_ip="192.168.1.50",
        dst_ip=None,
        src_port=None,
        dst_port=None,
        protocol=None,
        severity="high",
        score=0.7,
        rule_id=None,
        rule_version=None,
    )
    d3 = NormalizedDetection(
        detector_type="anomaly",
        detector_name="threshold",
        event_time="1500.0",  # 450s later -> outside window
        src_ip="192.168.1.50",
        dst_ip=None,
        src_port=None,
        dst_port=None,
        protocol=None,
        severity="medium",
        score=0.3,
        rule_id=None,
        rule_version=None,
    )

    groups = correlate_detections([d1, d2, d3], time_window_seconds=300)
    assert len(groups) == 2
    assert len(groups[0].detections) == 2
    assert len(groups[1].detections) == 1


def test_correlation_distinct_src_ips():
    """Detections from distinct IPs must not be merged into the same incident."""
    d1 = NormalizedDetection(
        detector_type="signature",
        detector_name="snort3",
        event_time="1000.0",
        src_ip="10.0.0.1",
        dst_ip=None,
        src_port=None,
        dst_port=None,
        protocol=None,
        severity="high",
        score=None,
        rule_id="1:100:1",
        rule_version="1",
    )
    d2 = NormalizedDetection(
        detector_type="signature",
        detector_name="snort3",
        event_time="1010.0",
        src_ip="10.0.0.2",
        dst_ip=None,
        src_port=None,
        dst_port=None,
        protocol=None,
        severity="high",
        score=None,
        rule_id="1:100:1",
        rule_version="1",
    )

    groups = correlate_detections([d1, d2], time_window_seconds=300)
    assert len(groups) == 2
    assert groups[0].group_key != groups[1].group_key


# ── 5. Deterministic Risk Scoring ─────────────────────────────────────────────

def test_risk_scoring_factors_complete():
    """Verify deterministic scoring factor breakdown is fully populated."""
    sig = NormalizedDetection(
        detector_type="signature",
        detector_name="snort3",
        event_time="100.0",
        src_ip="10.0.0.1",
        dst_ip=None,
        src_port=None,
        dst_port=None,
        protocol=None,
        severity="high",
        score=None,
        rule_id="1:100:1",
        rule_version="1",
    )
    anom = NormalizedDetection(
        detector_type="anomaly",
        detector_name="threshold",
        event_time="100.0",
        src_ip="10.0.0.1",
        dst_ip=None,
        src_port=None,
        dst_port=None,
        protocol=None,
        severity="high",
        score=0.85,
        rule_id=None,
        rule_version=None,
    )

    decision = compute_risk_score([sig, anom])
    assert "signature_signal" in decision.factors
    assert "anomaly_band" in decision.factors
    assert "repeated_behavior" in decision.factors
    assert "independent_corroboration" in decision.factors
    assert decision.factors["independent_corroboration"]["has_both"] is True
    assert decision.risk_score >= 50.0


def test_risk_scoring_100x_repeatability():
    """Run risk scorer 100 times on identical input to confirm absolute determinism."""
    dets = [
        NormalizedDetection(
            detector_type="signature",
            detector_name="snort3",
            event_time="1.0",
            src_ip="1.1.1.1",
            dst_ip=None,
            src_port=None,
            dst_port=None,
            protocol=None,
            severity="critical",
            score=None,
            rule_id="1:200:1",
            rule_version="1",
        ),
        NormalizedDetection(
            detector_type="anomaly",
            detector_name="threshold",
            event_time="2.0",
            src_ip="1.1.1.1",
            dst_ip=None,
            src_port=None,
            dst_port=None,
            protocol=None,
            severity="high",
            score=0.92,
            rule_id=None,
            rule_version=None,
        ),
    ]

    baseline = compute_risk_score(dets)
    for _ in range(100):
        current = compute_risk_score(dets)
        assert current.risk_score == baseline.risk_score
        assert current.severity == baseline.severity
        assert current.factors == baseline.factors


# ── 6. Run State Machine & Lifecycle ──────────────────────────────────────────

def test_run_state_transitions():
    """Verify permitted and rejected state transitions."""
    assert can_transition(RunStatus.queued, RunStatus.running) is True
    assert can_transition(RunStatus.queued, RunStatus.cancelled) is True
    assert can_transition(RunStatus.running, RunStatus.completed) is True
    assert can_transition(RunStatus.running, RunStatus.failed) is True

    # Terminal states cannot transition back
    assert can_transition(RunStatus.completed, RunStatus.running) is False
    assert can_transition(RunStatus.failed, RunStatus.running) is False
    assert can_transition(RunStatus.cancelled, RunStatus.running) is False

    with pytest.raises(ConflictError):
        assert_transition(RunStatus.completed, RunStatus.running)


# ── 7. Reproducible Lab Fixture Verification ─────────────────────────────────

def test_lab_pcap_fixtures_exist_and_valid():
    """Verify that all standard lab PCAP fixtures exist with valid PCAP headers."""
    pcap_dir = Path("data/pcaps")
    fixtures = ["port_scan.pcap", "dns_anomaly.pcap", "brute_force.pcap", "benign.pcap"]
    
    for f in fixtures:
        p = pcap_dir / f
        assert p.exists(), f"Missing lab fixture: {f}"
        assert p.stat().st_size > 0, f"Empty lab fixture: {f}"
        # Validate PCAP magic bytes (0xd4c3b2a1 or 0xa1b2c3d4)
        with p.open("rb") as fh:
            magic = fh.read(4)
        assert magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a"), (
            f"Invalid PCAP header in {f}"
        )
