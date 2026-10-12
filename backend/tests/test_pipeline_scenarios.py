"""
End-to-end pipeline integration tests across all core detection scenarios:
  1. Scenario A: Port scan (TCP SYN burst across multiple ports)
  2. Scenario B: DNS anomaly (High query rate and high-entropy DNS tunneling)
  3. Scenario C: Brute force / repeated connections
  4. Scenario D: Benign baseline traffic (no false alarms)
"""
from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from app.db.session import create_all_tables
from app.main import app


@pytest.fixture(autouse=True)
async def setup_db():
    await create_all_tables()


@pytest.mark.asyncio
async def test_scenario_port_scan_pipeline():
    """Verify port scan PCAP triggers an anomaly detection, builds incident, and calculates risk score."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # Create and execute run
        create_res = await ac.post(
            "/api/runs",
            json={
                "input_path": "port_scan.pcap",
                "scenario_id": "port_scan_scenario",
                "detector_mode": "hybrid",
            },
        )
        assert create_res.status_code == 201
        run_id = create_res.json()["run_id"]

        exec_res = await ac.post(f"/api/runs/{run_id}/execute")
        assert exec_res.status_code == 200
        exec_data = exec_res.json()
        assert exec_data["status"] in ("completed", "partial_failure")
        assert exec_data["incidents_created"] >= 1

        # Check incidents
        inc_res = await ac.get(f"/api/incidents?run_id={run_id}")
        assert inc_res.status_code == 200
        incidents = inc_res.json()
        assert len(incidents) >= 1
        
        # Verify incident properties
        incident = incidents[0]
        assert incident["risk_score"] > 0
        assert incident["detection_count"] >= 1


@pytest.mark.asyncio
async def test_scenario_dns_anomaly_pipeline():
    """Verify DNS anomaly PCAP triggers DNS detection and correlates incident."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        create_res = await ac.post(
            "/api/runs",
            json={
                "input_path": "dns_anomaly.pcap",
                "scenario_id": "dns_anomaly_scenario",
                "detector_mode": "hybrid",
            },
        )
        assert create_res.status_code == 201
        run_id = create_res.json()["run_id"]

        exec_res = await ac.post(f"/api/runs/{run_id}/execute")
        assert exec_res.status_code == 200
        exec_data = exec_res.json()
        assert exec_data["incidents_created"] >= 1

        inc_res = await ac.get(f"/api/incidents?run_id={run_id}")
        assert inc_res.status_code == 200
        incidents = inc_res.json()
        assert len(incidents) >= 1
        assert incidents[0]["risk_score"] > 0


@pytest.mark.asyncio
async def test_scenario_brute_force_pipeline():
    """Verify high-frequency connection attempt PCAP triggers anomaly and incident."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        create_res = await ac.post(
            "/api/runs",
            json={
                "input_path": "brute_force.pcap",
                "scenario_id": "brute_force_scenario",
                "detector_mode": "hybrid",
            },
        )
        assert create_res.status_code == 201
        run_id = create_res.json()["run_id"]

        exec_res = await ac.post(f"/api/runs/{run_id}/execute")
        assert exec_res.status_code == 200
        exec_data = exec_res.json()
        assert exec_data["status"] in ("completed", "partial_failure")
        assert exec_data["incidents_created"] >= 1


@pytest.mark.asyncio
async def test_scenario_benign_traffic_pipeline():
    """Verify benign traffic PCAP does not produce high-severity incidents."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        create_res = await ac.post(
            "/api/runs",
            json={
                "input_path": "benign.pcap",
                "scenario_id": "benign_scenario",
                "detector_mode": "hybrid",
            },
        )
        assert create_res.status_code == 201
        run_id = create_res.json()["run_id"]

        exec_res = await ac.post(f"/api/runs/{run_id}/execute")
        assert exec_res.status_code == 200
        exec_data = exec_res.json()
        
        # In benign traffic, either 0 incidents or 0 detections
        inc_res = await ac.get(f"/api/incidents?run_id={run_id}")
        assert inc_res.status_code == 200
        incidents = inc_res.json()
        for inc in incidents:
            assert inc["severity"] != "critical"
            assert inc["severity"] != "high"
