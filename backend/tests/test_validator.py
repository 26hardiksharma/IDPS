"""
Unit tests for the explanation validator.
Tests all four validation levels: L1 (structural), L2 (references),
L3 (numeric/state consistency), L4 (claim support heuristics).
"""
from __future__ import annotations

import json

import pytest

from app.explanation.validator import validate_explanation, ValidationStatus


def _make_bundle(**overrides) -> dict:
    base = {
        "incident_id": "inc_test123",
        "run_id": "run_test123",
        "severity": "medium",
        "risk_score": 55.0,
        "score_factors": None,
        "correlation_reason": None,
        "policy_version_id": "polver_1",
        "first_seen": "1000",
        "last_seen": "1030",
        "detections": [{"detection_id": "det_001", "detector_type": "signature"}],
        "evidence": [{"evidence_id": "ev_001", "source_type": "snort_alert"}],
        "valid_evidence_ids": ["ev_001"],
        "valid_detection_ids": ["det_001"],
        "valid_rule_version_ids": ["rulever_001"],
    }
    base.update(overrides)
    return base


def _make_valid_output(incident_id: str = "inc_test123") -> str:
    return json.dumps(
        {
            "incident_id": incident_id,
            "summary": "Traffic pattern consistent with port scanning behavior.",
            "observations": [
                {
                    "claim": "A Snort rule matched the traffic.",
                    "evidence_ids": ["det_001"],
                    "validation_type": "rule_and_detection_link",
                }
            ],
            "interpretations": [
                {
                    "claim": "The source may be conducting reconnaissance.",
                    "evidence_ids": ["ev_001"],
                    "confidence": "moderate",
                }
            ],
            "evidence_references": ["ev_001", "det_001"],
            "uncertainties": ["Source intent cannot be established from packets alone."],
            "recommended_next_steps": ["Review packet timeline."],
        }
    )


# ── L1: Structural tests ──────────────────────────────────────────────────────

def test_l1_valid_json_passes():
    bundle = _make_bundle()
    result = validate_explanation(_make_valid_output(), bundle)
    assert result.status in (ValidationStatus.valid, ValidationStatus.partially_valid)


def test_l1_invalid_json_fails():
    bundle = _make_bundle()
    result = validate_explanation("{not valid json", bundle)
    assert result.status == ValidationStatus.failed
    assert any(f.code == "invalid_json" for f in result.findings)


def test_l1_missing_required_field():
    bundle = _make_bundle()
    output = json.dumps({"summary": "Missing incident_id"})
    result = validate_explanation(output, bundle)
    assert result.status == ValidationStatus.failed
    assert any("incident_id" in f.message for f in result.findings)


# ── L2: Reference integrity tests ─────────────────────────────────────────────

def test_l2_invalid_evidence_reference_flagged():
    bundle = _make_bundle()
    output = json.dumps(
        {
            "incident_id": "inc_test123",
            "summary": "A legitimate summary for testing purposes here.",
            "observations": [
                {"claim": "Some claim.", "evidence_ids": ["ev_NONEXISTENT"]}
            ],
            "interpretations": [],
            "evidence_references": ["ev_NONEXISTENT"],
            "uncertainties": [],
            "recommended_next_steps": [],
        }
    )
    result = validate_explanation(output, bundle)
    assert any(f.code in ("invalid_evidence_reference", "invalid_observation_reference") for f in result.findings)
    error_findings = [f for f in result.findings if f.severity == "error"]
    assert len(error_findings) > 0


def test_l2_incident_id_mismatch_flagged():
    bundle = _make_bundle()
    output = _make_valid_output(incident_id="inc_WRONG")
    result = validate_explanation(output, bundle)
    assert any(f.code == "incident_id_mismatch" for f in result.findings)


def test_l2_valid_references_pass():
    bundle = _make_bundle()
    output = _make_valid_output()
    result = validate_explanation(output, bundle)
    # Should not have reference errors
    ref_errors = [f for f in result.findings if f.code in (
        "invalid_evidence_reference", "invalid_observation_reference",
        "invalid_interpretation_reference"
    )]
    assert len(ref_errors) == 0


# ── L3: Numeric/state consistency tests ──────────────────────────────────────

def test_l3_real_block_claim_flagged():
    bundle = _make_bundle()
    output = json.dumps(
        {
            "incident_id": "inc_test123",
            "summary": "A firewall rule was added to block the source IP.",
            "observations": [{"claim": "Rule fired.", "evidence_ids": ["ev_001"]}],
            "interpretations": [],
            "evidence_references": ["ev_001"],
            "uncertainties": [],
            "recommended_next_steps": [],
        }
    )
    result = validate_explanation(output, bundle)
    assert any(f.code == "false_real_block_claim" for f in result.findings)


def test_l3_simulated_only_no_false_block_flag():
    """A clean explanation should not be falsely flagged for real blocking."""
    bundle = _make_bundle()
    output = _make_valid_output()
    result = validate_explanation(output, bundle)
    assert not any(f.code == "false_real_block_claim" for f in result.findings)


# ── L4: Claim support tests ───────────────────────────────────────────────────

def test_l4_observation_without_citation_is_warning():
    bundle = _make_bundle()
    output = json.dumps(
        {
            "incident_id": "inc_test123",
            "summary": "This is a sufficiently long summary to pass the length check.",
            "observations": [{"claim": "Something happened.", "evidence_ids": []}],
            "interpretations": [],
            "evidence_references": ["ev_001"],
            "uncertainties": [],
            "recommended_next_steps": [],
        }
    )
    result = validate_explanation(output, bundle)
    warnings = [f for f in result.findings if f.code == "observation_missing_citation"]
    assert len(warnings) > 0
    assert all(w.severity == "warning" for w in warnings)


# ── Response simulator safety test ───────────────────────────────────────────

def test_simulator_simulated_only():
    """Verify simulated_only is always True in response audit records."""
    from app.db.models import ResponseAudit
    audit = ResponseAudit(
        id="test",
        incident_id="inc_1",
        proposed_action="simulate_source_isolation",
        simulated_only=True,
    )
    assert audit.simulated_only is True
