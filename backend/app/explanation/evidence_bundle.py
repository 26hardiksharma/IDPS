"""
Evidence Bundle Builder — retrieves only the bounded, structured evidence
needed for explanation generation.

The bundle includes:
- Incident metadata and risk decision
- Constituent detection records
- Evidence records linked to those detections
- Rule/model version identifiers
- Scoring policy version

It does NOT include raw PCAP payloads or unrestricted database access.
"""
from __future__ import annotations

import json
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import NotFoundError
from app.db.models import (
    Detection,
    Evidence,
    Incident,
    IncidentDetection,
)
from app.provenance.repository import ProvenanceRepository


async def build_evidence_bundle(
    incident_id: str,
    db: AsyncSession,
) -> dict[str, Any]:
    """
    Build a bounded evidence bundle for incident *incident_id*.
    Returns a dict safe to pass to the LLM prompt.
    """
    repo = ProvenanceRepository(db)
    incident = await repo.get_incident(incident_id)

    # Collect detection and evidence records
    detections_data: list[dict[str, Any]] = []
    evidence_ids: set[str] = set()

    for link in incident.detection_links:
        det: Detection = link.detection
        det_data: dict[str, Any] = {
            "detection_id": det.id,
            "detector_type": det.detector_type.value if det.detector_type else det.detector_type,
            "detector_name": det.detector_name,
            "event_time": det.event_time,
            "src_ip": det.src_ip,
            "dst_ip": det.dst_ip,
            "src_port": det.src_port,
            "dst_port": det.dst_port,
            "protocol": det.protocol,
            "severity": det.severity,
            "score": det.score,
            "rule_version_id": det.rule_version_id,
            "model_version_id": det.model_version_id,
            "normalizer_version": det.normalizer_version,
        }
        # Include feature snapshot if present (anomaly only)
        if det.feature_snapshot:
            try:
                det_data["feature_snapshot"] = json.loads(det.feature_snapshot)
            except (json.JSONDecodeError, TypeError):
                det_data["feature_snapshot"] = None

        if det.evidence_id:
            evidence_ids.add(det.evidence_id)

        detections_data.append(det_data)

    # Load evidence records
    evidence_data: list[dict[str, Any]] = []
    for ev_id in evidence_ids:
        try:
            ev = await db.get(Evidence, ev_id)
            if ev:
                evidence_data.append(
                    {
                        "evidence_id": ev.id,
                        "source_type": ev.source_type,
                        "event_time": ev.event_time,
                        "src_ip": ev.src_ip,
                        "dst_ip": ev.dst_ip,
                        "src_port": ev.src_port,
                        "dst_port": ev.dst_port,
                        "protocol": ev.protocol,
                        "content_hash": ev.content_hash,
                        # Include normalized_data but omit raw payloads
                        "normalized_data": (
                            json.loads(ev.normalized_data)
                            if ev.normalized_data
                            else None
                        ),
                    }
                )
        except Exception:
            pass

    # Scoring factors
    score_factors: dict[str, Any] | None = None
    if incident.score_factors:
        try:
            score_factors = json.loads(incident.score_factors)
        except (json.JSONDecodeError, TypeError):
            score_factors = None

    bundle: dict[str, Any] = {
        "incident_id": incident.id,
        "run_id": incident.run_id,
        "severity": incident.severity.value if incident.severity else incident.severity,
        "risk_score": incident.risk_score,
        "score_factors": score_factors,
        "correlation_reason": incident.correlation_reason,
        "policy_version_id": incident.policy_version_id,
        "first_seen": incident.first_seen,
        "last_seen": incident.last_seen,
        "detections": detections_data,
        "evidence": evidence_data,
        # Valid IDs the LLM may cite
        "valid_evidence_ids": [e["evidence_id"] for e in evidence_data],
        "valid_detection_ids": [d["detection_id"] for d in detections_data],
        "valid_rule_version_ids": [
            d["rule_version_id"]
            for d in detections_data
            if d.get("rule_version_id")
        ],
    }
    return bundle
