"""
Integration tests for FastAPI REST API endpoints.
Tests health, rules, metrics, runs, incidents, explanations, and response-simulations.
"""
from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.db.session import create_all_tables


@pytest.fixture(autouse=True)
async def setup_db():
    await create_all_tables()


@pytest.mark.asyncio
async def test_health_check():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "xai-idps"


@pytest.mark.asyncio
async def test_rules_api():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.get("/api/rules")
    assert response.status_code == 200
    rules = response.json()
    assert isinstance(rules, list)


@pytest.mark.asyncio
async def test_metrics_api():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.get("/api/metrics")
    assert response.status_code == 200
    metrics = response.json()
    assert "total_runs" in metrics
    assert "total_incidents" in metrics


@pytest.mark.asyncio
async def test_run_creation_and_execution_lifecycle():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # 1. Create run for port_scan.pcap
        create_res = await ac.post(
            "/api/runs",
            json={
                "input_path": "port_scan.pcap",
                "scenario_id": "test_port_scan",
                "detector_mode": "hybrid",
            },
        )
        assert create_res.status_code == 201
        run_data = create_res.json()
        assert "run_id" in run_data
        run_id = run_data["run_id"]
        assert run_data["status"] == "queued"

        # 2. Get run summary
        get_res = await ac.get(f"/api/runs/{run_id}")
        assert get_res.status_code == 200
        assert get_res.json()["run_id"] == run_id

        # 3. List runs
        list_res = await ac.get("/api/runs")
        assert list_res.status_code == 200
        run_ids = [r["run_id"] for r in list_res.json()]
        assert run_id in run_ids

        # 4. Execute the run
        exec_res = await ac.post(f"/api/runs/{run_id}/execute")
        assert exec_res.status_code == 200
        exec_data = exec_res.json()
        assert exec_data["status"] in ("completed", "partial_failure")
        assert exec_data["run_id"] == run_id

        # 5. List incidents created by this run
        inc_res = await ac.get(f"/api/incidents?run_id={run_id}")
        assert inc_res.status_code == 200
        incidents = inc_res.json()
        assert len(incidents) >= 1
        incident_id = incidents[0]["incident_id"]

        # 6. Fetch incident detail
        detail_res = await ac.get(f"/api/incidents/{incident_id}")
        assert detail_res.status_code == 200
        incident_detail = detail_res.json()
        assert incident_detail["incident_id"] == incident_id
        assert incident_detail["risk_score"] > 0
        assert len(incident_detail["detections"]) > 0

        # 7. Update incident status
        patch_res = await ac.patch(
            f"/api/incidents/{incident_id}/status",
            json={"status": "under_review", "analyst_notes": "Triaged by integration test"},
        )
        assert patch_res.status_code == 200
        assert patch_res.json()["status"] == "under_review"

        # 8. Create response simulation
        sim_res = await ac.post(
            f"/api/incidents/{incident_id}/response-simulations",
            json={
                "proposed_action": "simulate_source_isolation",
                "action_target": "192.168.1.50",
                "action_scope": "source_ip",
                "dry_run_rule": "iptables -A INPUT -s 192.168.1.50 -j DROP",
                "actor": "security_analyst_test",
            },
        )
        assert sim_res.status_code == 201
        sim_data = sim_res.json()
        assert sim_data["simulated_only"] is True
        assert sim_data["simulation_status"] == "simulated"

        # 9. Verify standalone response-simulations listing
        sim_list_res = await ac.get(f"/api/response-simulations?incident_id={incident_id}")
        assert sim_list_res.status_code == 200
        sim_list = sim_list_res.json()
        assert len(sim_list) >= 1
        assert sim_list[0]["simulated_only"] is True
