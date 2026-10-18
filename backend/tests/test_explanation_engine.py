"""
Comprehensive test suite for XAI-IDPS Explanation Engine, Grounding Validator,
Relational Citation Persistence, and End-to-End Forensic Provenance.
"""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from app.db.models import ValidationStatus
from app.db.session import create_all_tables
from app.explanation.ollama_client import OllamaUnavailableError, generate_explanation
from app.explanation.validator import validate_explanation
from app.main import app


@pytest.fixture(autouse=True)
async def setup_db():
    await create_all_tables()


# ── 1. Advanced Grounding Validator Tests ─────────────────────────────────────

def test_validator_severity_inconsistency_flagged():
    bundle = {
        "incident_id": "inc_val_01",
        "run_id": "run_01",
        "severity": "low",
        "risk_score": 15.0,
        "valid_evidence_ids": ["ev_01"],
        "valid_detection_ids": ["det_01"],
        "detections": [{"detection_id": "det_01", "detector_type": "signature"}],
        "evidence": [{"evidence_id": "ev_01"}],
    }
    explanation_json = json.dumps({
        "incident_id": "inc_val_01",
        "summary": "This is a critical incident with catastrophic damage.",
        "observations": [{"claim": "This event is critical severity.", "evidence_ids": ["ev_01"]}],
        "interpretations": [],
        "evidence_references": ["ev_01"],
        "uncertainties": [],
        "recommended_next_steps": [],
    })
    result = validate_explanation(explanation_json, bundle)
    assert any(f.code == "severity_inconsistency" for f in result.findings)
    assert result.status == ValidationStatus.invalid


def test_validator_nonexistent_signature_claim_flagged():
    bundle = {
        "incident_id": "inc_val_02",
        "run_id": "run_02",
        "severity": "high",
        "risk_score": 75.0,
        "valid_evidence_ids": ["ev_02"],
        "valid_detection_ids": ["det_02"],
        # ONLY anomaly detector fired — NO signature detection
        "detections": [{"detection_id": "det_02", "detector_type": "anomaly"}],
        "evidence": [{"evidence_id": "ev_02"}],
    }
    explanation_json = json.dumps({
        "incident_id": "inc_val_02",
        "summary": "Snort signature triggered on port scanning attack vector.",
        "observations": [{"claim": "Snort signature ET SCAN fired.", "evidence_ids": ["ev_02"]}],
        "interpretations": [],
        "evidence_references": ["ev_02"],
        "uncertainties": [],
        "recommended_next_steps": [],
    })
    result = validate_explanation(explanation_json, bundle)
    assert any(f.code == "nonexistent_signature_claim" for f in result.findings)
    assert result.status == ValidationStatus.invalid


def test_validator_nonexistent_anomaly_claim_flagged():
    bundle = {
        "incident_id": "inc_val_03",
        "run_id": "run_03",
        "severity": "medium",
        "risk_score": 50.0,
        "valid_evidence_ids": ["ev_03"],
        "valid_detection_ids": ["det_03"],
        # ONLY signature detector fired — NO anomaly detection
        "detections": [{"detection_id": "det_03", "detector_type": "signature"}],
        "evidence": [{"evidence_id": "ev_03"}],
    }
    explanation_json = json.dumps({
        "incident_id": "inc_val_03",
        "summary": "Isolation forest anomaly engine detected statistical rate outlier.",
        "observations": [{"claim": "Anomaly score exceeded threshold.", "evidence_ids": ["ev_03"]}],
        "interpretations": [],
        "evidence_references": ["ev_03"],
        "uncertainties": [],
        "recommended_next_steps": [],
    })
    result = validate_explanation(explanation_json, bundle)
    assert any(f.code == "nonexistent_anomaly_claim" for f in result.findings)
    assert result.status == ValidationStatus.invalid


def test_validator_score_misrepresented_as_probability_flagged():
    bundle = {
        "incident_id": "inc_val_04",
        "run_id": "run_04",
        "severity": "high",
        "risk_score": 85.0,
        "valid_evidence_ids": ["ev_04"],
        "valid_detection_ids": ["det_04"],
        "detections": [{"detection_id": "det_04", "detector_type": "signature"}],
        "evidence": [{"evidence_id": "ev_04"}],
    }
    explanation_json = json.dumps({
        "incident_id": "inc_val_04",
        "summary": "Analysis indicates an 85% probability of successful intrusion.",
        "observations": [{"claim": "The attack has 85% probability.", "evidence_ids": ["ev_04"]}],
        "interpretations": [],
        "evidence_references": ["ev_04"],
        "uncertainties": [],
        "recommended_next_steps": [],
    })
    result = validate_explanation(explanation_json, bundle)
    assert any(f.code == "score_misrepresented_as_probability" for f in result.findings)


def test_validator_all_valid_citation_ids_pass():
    bundle = {
        "incident_id": "inc_val_05",
        "run_id": "run_05",
        "severity": "high",
        "risk_score": 80.0,
        "valid_evidence_ids": ["ev_05"],
        "valid_detection_ids": ["det_05"],
        "valid_rule_version_ids": ["rule_v1.0"],
        "valid_model_version_ids": ["iforest_v1.0"],
        "all_valid_citation_ids": ["ev_05", "det_05", "rule_v1.0", "iforest_v1.0", "pol_v1.0", "run_05"],
        "detections": [
            {"detection_id": "det_05", "detector_type": "signature", "rule_version_id": "rule_v1.0"},
            {"detection_id": "det_06", "detector_type": "anomaly", "model_version_id": "iforest_v1.0"},
        ],
        "evidence": [{"evidence_id": "ev_05"}],
    }
    explanation_json = json.dumps({
        "incident_id": "inc_val_05",
        "summary": "Correlated signature and anomaly detection observed on network host.",
        "observations": [{"claim": "Snort matched rule_v1.0 on traffic ev_05.", "evidence_ids": ["ev_05"]}],
        "interpretations": [{"claim": "Possible host enumeration behavior.", "evidence_ids": ["det_05"]}],
        "evidence_references": ["ev_05", "det_05", "rule_v1.0", "pol_v1.0"],
        "uncertainties": ["Attacker origin unverified."],
        "recommended_next_steps": ["Review host network connectivity."],
    })
    result = validate_explanation(explanation_json, bundle)
    assert result.status == ValidationStatus.valid
    assert result.validated_output is not None
    assert "ev_05" in result.validated_output.evidence_references


# ── 2. Local Ollama Client Unit Tests ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_ollama_client_success():
    req = httpx.Request("POST", "http://localhost:11434/api/generate")
    mock_response = httpx.Response(
        status_code=200,
        json={"message": {"content": json.dumps({"summary": "Clean summary", "incident_id": "inc_1"})}},
        request=req,
    )
    with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_response):
        raw_output, latency_ms = await generate_explanation({"incident_id": "inc_1"})
        assert raw_output is not None
        assert "Clean summary" in raw_output
        assert latency_ms >= 0


@pytest.mark.asyncio
async def test_ollama_client_connection_error_raises_unavailable():
    with patch("httpx.AsyncClient.post", side_effect=httpx.ConnectError("Connection refused")):
        with pytest.raises(OllamaUnavailableError) as exc_info:
            await generate_explanation({"incident_id": "inc_1"})
        assert "not reachable" in str(exc_info.value).lower()


@pytest.mark.asyncio
async def test_ollama_client_timeout_raises_unavailable():
    with patch("httpx.AsyncClient.post", side_effect=httpx.TimeoutException("Read timed out")):
        with pytest.raises(OllamaUnavailableError) as exc_info:
            await generate_explanation({"incident_id": "inc_1"})
        assert "timed out" in str(exc_info.value).lower()


@pytest.mark.asyncio
async def test_ollama_client_http_500_raises_unavailable():
    req = httpx.Request("POST", "http://localhost:11434/api/generate")
    mock_500 = httpx.Response(status_code=500, text="Internal Server Error", request=req)
    with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_500):
        with pytest.raises(OllamaUnavailableError) as exc_info:
            await generate_explanation({"incident_id": "inc_1"})
        assert "500" in str(exc_info.value)


# ── 3. API Integration: Explanations, Citations & Provenance ──────────────────

@pytest.mark.asyncio
async def test_explanation_lifecycle_with_relational_citations():
    """Create run -> execute -> explain with mock Ollama -> verify relational citations."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # 1. Run pipeline
        create_res = await ac.post(
            "/api/runs",
            json={
                "input_path": "port_scan.pcap",
                "scenario_id": "provenance_test_run",
                "detector_mode": "hybrid",
            },
        )
        assert create_res.status_code == 201
        run_id = create_res.json()["run_id"]

        exec_res = await ac.post(f"/api/runs/{run_id}/execute")
        assert exec_res.status_code == 200

        # 2. Get incident
        inc_res = await ac.get(f"/api/incidents?run_id={run_id}")
        assert inc_res.status_code == 200
        incidents = inc_res.json()
        assert len(incidents) >= 1
        incident_id = incidents[0]["incident_id"]

        # Fetch incident detail to know valid detection/evidence IDs
        detail_res = await ac.get(f"/api/incidents/{incident_id}")
        assert detail_res.status_code == 200
        det_id = detail_res.json()["detections"][0]["detection_id"]

        # Mock Ollama response generating valid grounded citations
        mock_llm_json = json.dumps({
            "incident_id": incident_id,
            "summary": "Valid explanation generated by local model for integration testing.",
            "observations": [{"claim": f"Detection {det_id} triggered on scan traffic.", "evidence_ids": [det_id]}],
            "interpretations": [{"claim": "Reconnaissance sweep detected across destination ports.", "evidence_ids": [det_id]}],
            "evidence_references": [det_id, run_id],
            "uncertainties": ["Attacker intent cannot be proven."],
            "recommendations": ["Inspect source host logs."],
            "limitations": ["PCAP captured for short interval."],
        })

        with patch("app.api.incidents.generate_explanation", new_callable=AsyncMock, return_value=(mock_llm_json, 120)):
            explain_res = await ac.post(f"/api/incidents/{incident_id}/explanations")
            assert explain_res.status_code == 201
            exp_data = explain_res.json()

            assert exp_data["incident_id"] == incident_id
            assert exp_data["validation_status"] in ("valid", "partially_valid")
            assert len(exp_data["citations"]) >= 1
            citation = exp_data["citations"][0]
            assert citation["record_id"] == det_id
            assert citation["record_type"] == "detection"
            explanation_id = exp_data["explanation_id"]

            # 3. Retrieve single explanation by ID
            get_exp_res = await ac.get(f"/api/explanations/{explanation_id}")
            assert get_exp_res.status_code == 200
            single_exp = get_exp_res.json()
            assert single_exp["explanation_id"] == explanation_id
            assert len(single_exp["citations"]) >= 1

            # 4. List explanations for incident
            list_exp_res = await ac.get(f"/api/incidents/{incident_id}/explanations")
            assert list_exp_res.status_code == 200
            exp_list = list_exp_res.json()
            assert len(exp_list) >= 1
            assert exp_list[0]["citations"][0]["record_id"] == det_id


@pytest.mark.asyncio
async def test_ollama_unavailable_records_failure_without_corrupting_incident():
    """When Ollama is unreachable, explanation failure is recorded honestly without losing incident data."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        create_res = await ac.post(
            "/api/runs",
            json={"input_path": "port_scan.pcap", "detector_mode": "hybrid"},
        )
        run_id = create_res.json()["run_id"]
        await ac.post(f"/api/runs/{run_id}/execute")

        inc_res = await ac.get(f"/api/incidents?run_id={run_id}")
        incident_id = inc_res.json()[0]["incident_id"]

        with patch("app.api.incidents.generate_explanation", side_effect=OllamaUnavailableError("Ollama offline")):
            explain_res = await ac.post(f"/api/incidents/{incident_id}/explanations")
            assert explain_res.status_code == 201
            exp_data = explain_res.json()
            assert exp_data["validation_status"] == "failed"
            assert exp_data["validated_output"] is None
            assert any(f["code"] == "ollama_unavailable" for f in exp_data["validation_findings"])

            # Verify incident still exists intact
            detail_res = await ac.get(f"/api/incidents/{incident_id}")
            assert detail_res.status_code == 200
            assert detail_res.json()["incident_id"] == incident_id


@pytest.mark.asyncio
async def test_full_provenance_chain_endpoint():
    """Verify GET /api/incidents/{incident_id}/provenance returns complete 7-step chain."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # 1. Run pipeline
        create_res = await ac.post(
            "/api/runs",
            json={"input_path": "port_scan.pcap", "detector_mode": "hybrid"},
        )
        run_id = create_res.json()["run_id"]
        await ac.post(f"/api/runs/{run_id}/execute")

        inc_res = await ac.get(f"/api/incidents?run_id={run_id}")
        incident_id = inc_res.json()[0]["incident_id"]

        # 2. Add simulated response
        sim_res = await ac.post(
            f"/api/incidents/{incident_id}/response-simulations",
            json={
                "proposed_action": "simulate_source_isolation",
                "action_target": "192.168.1.100",
                "action_scope": "host",
                "actor": "analyst_provenance_test",
            },
        )
        assert sim_res.status_code == 201
        sim_data = sim_res.json()
        assert sim_data["simulated_only"] is True

        # 3. Retrieve end-to-end provenance graph
        prov_res = await ac.get(f"/api/incidents/{incident_id}/provenance")
        assert prov_res.status_code == 200
        prov = prov_res.json()

        # Check all graph nodes
        assert prov["incident_id"] == incident_id
        assert prov["run"] is not None
        assert prov["run"]["run_id"] == run_id
        assert prov["policy_version"] is not None
        assert len(prov["detections"]) >= 1
        assert len(prov["simulations"]) >= 1
        assert prov["simulations"][0]["simulated_only"] is True

        # Check provenance chain stages
        chain_stages = [step["stage"] for step in prov["provenance_chain"]]
        expected_stages = [
            "Analysis Run",
            "Evidence",
            "Detections",
            "Incident",
            "Policy Version",
            "Explanation",
            "Response Audit",
        ]
        for stage in expected_stages:
            assert stage in chain_stages


@pytest.mark.asyncio
async def test_provenance_nonexistent_incident_returns_404():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.get("/api/incidents/inc_NONEXISTENT_999/provenance")
        assert res.status_code == 404
