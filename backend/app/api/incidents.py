"""
Incidents API router — GET /api/incidents, GET /api/incidents/{incident_id},
POST /api/incidents/{incident_id}/explanations,
POST /api/incidents/{incident_id}/response-simulations
"""
from __future__ import annotations

import json
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas import (
    CreateSimulationRequest,
    DetectionSummary,
    ExplanationResponse,
    IncidentChatRequest,
    IncidentChatResponse,
    IncidentDetailResponse,
    IncidentSummaryResponse,
    SimulationResponse,
    UpdateIncidentStatusRequest,
)
from app.core.errors import OllamaUnavailableError
from app.core.logging import get_logger
from app.db.models import ValidationStatus
from app.db.session import get_db_session
from app.explanation.evidence_bundle import build_evidence_bundle
from app.explanation.ollama_client import (
    PROMPT_TEMPLATE_VERSION,
    generate_explanation,
)
from app.explanation.validator import validate_explanation
from app.provenance.repository import ProvenanceRepository
from app.response.simulator import record_simulation

logger = get_logger(__name__)
router = APIRouter(prefix="/api/incidents", tags=["incidents"])

DbDep = Annotated[AsyncSession, Depends(get_db_session)]


@router.get("", response_model=list[IncidentSummaryResponse])
async def list_incidents(
    db: DbDep,
    run_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(50, le=200),
    offset: int = Query(0),
) -> list[IncidentSummaryResponse]:
    """List/filter incidents."""
    repo = ProvenanceRepository(db)
    incidents = await repo.list_incidents(
        run_id=run_id,
        severity=severity,
        status=status,
        limit=limit,
        offset=offset,
    )
    result = []
    for inc in incidents:
        # Get latest explanation status
        exp_status = None
        if inc.explanations:
            latest = max(inc.explanations, key=lambda e: e.created_at)
            exp_status = latest.validation_status.value if latest.validation_status else None
        result.append(
            IncidentSummaryResponse(
                incident_id=inc.id,
                run_id=inc.run_id,
                status=inc.status.value,
                severity=inc.severity.value,
                risk_score=inc.risk_score,
                first_seen=inc.first_seen,
                last_seen=inc.last_seen,
                policy_version_id=inc.policy_version_id,
                detection_count=len(inc.detection_links),
                explanation_status=exp_status,
                created_at=inc.created_at,
            )
        )
    return result


@router.get("/{incident_id}", response_model=IncidentDetailResponse)
async def get_incident(incident_id: str, db: DbDep) -> IncidentDetailResponse:
    """Return incident detail with constituent detections and provenance."""
    repo = ProvenanceRepository(db)
    inc = await repo.get_incident(incident_id)

    score_factors = None
    if inc.score_factors:
        try:
            score_factors = json.loads(inc.score_factors)
        except (json.JSONDecodeError, TypeError):
            score_factors = None

    detections = []
    for link in inc.detection_links:
        det = link.detection
        detections.append(
            DetectionSummary(
                detection_id=det.id,
                detector_type=det.detector_type.value if det.detector_type else None,
                detector_name=det.detector_name,
                event_time=det.event_time,
                src_ip=det.src_ip,
                dst_ip=det.dst_ip,
                severity=det.severity,
                score=det.score,
                rule_version_id=det.rule_version_id,
                model_version_id=det.model_version_id,
            )
        )

    from app.correlation.mitre_mapping import map_detections_to_mitre
    mitre_attack = map_detections_to_mitre([d.model_dump() for d in detections])

    return IncidentDetailResponse(
        incident_id=inc.id,
        run_id=inc.run_id,
        status=inc.status.value,
        severity=inc.severity.value,
        risk_score=inc.risk_score,
        score_factors=score_factors,
        correlation_reason=inc.correlation_reason,
        first_seen=inc.first_seen,
        last_seen=inc.last_seen,
        policy_version_id=inc.policy_version_id,
        detections=detections,
        mitre_attack=mitre_attack,
        created_at=inc.created_at,
        updated_at=inc.updated_at,
    )


@router.patch("/{incident_id}/status", response_model=dict)
async def update_incident_status(
    incident_id: str,
    body: UpdateIncidentStatusRequest,
    db: DbDep,
) -> dict:
    """Update the analyst review status of an incident."""
    repo = ProvenanceRepository(db)
    inc = await repo.update_incident_status(incident_id, body.status)
    return {"incident_id": inc.id, "status": inc.status.value}

@router.get("/{incident_id}/explanations", response_model=list[ExplanationResponse])
async def list_incident_explanations(
    incident_id: str,
    db: DbDep,
) -> list[ExplanationResponse]:
    """Return all explanations for a given incident, newest first."""
    repo = ProvenanceRepository(db)
    inc = await repo.get_incident(incident_id)

    result = []
    for exp in sorted(inc.explanations, key=lambda e: e.created_at, reverse=True):
        vo = None
        if exp.validated_output:
            try:
                vo = json.loads(exp.validated_output)
            except (json.JSONDecodeError, TypeError):
                vo = None

        vf = None
        if exp.validation_findings:
            try:
                vf = json.loads(exp.validation_findings)
            except (json.JSONDecodeError, TypeError):
                vf = None

        result.append(
            ExplanationResponse(
                explanation_id=exp.id,
                incident_id=exp.incident_id,
                model_id=exp.model_id,
                prompt_version=exp.prompt_version,
                validation_status=exp.validation_status.value
                if hasattr(exp.validation_status, "value")
                else str(exp.validation_status),
                validated_output=vo,
                validation_findings=vf,
                llm_latency_ms=exp.llm_latency_ms,
                created_at=exp.created_at,
            )
        )
    return result


@router.post("/{incident_id}/explanations", response_model=ExplanationResponse, status_code=201)
async def generate_incident_explanation(
    incident_id: str,
    db: DbDep,
) -> ExplanationResponse:
    """
    Generate (or regenerate) a local LLM explanation for the incident.
    LLM unavailability does not delete existing detections — it is
    recorded as explanation_unavailable.
    """
    from app.core.config import get_settings
    settings = get_settings()

    repo = ProvenanceRepository(db)
    # Confirm incident exists
    await repo.get_incident(incident_id)

    # Build bounded evidence bundle
    bundle = await build_evidence_bundle(incident_id, db)

    raw_output: str | None = None
    latency_ms: int = 0
    validation_status = ValidationStatus.failed
    validated_output = None
    validation_findings: list = []

    try:
        raw_output, latency_ms = await generate_explanation(bundle)

        if raw_output:
            vr = validate_explanation(raw_output, bundle)
            validation_status = vr.status
            validation_findings = [f.__dict__ for f in vr.findings]
            if vr.validated_output:
                validated_output = vr.validated_output.model_dump()
                validated_output["observed_facts"] = [
                    o["claim"] if isinstance(o, dict) else o.claim
                    for o in validated_output.get("observations", [])
                ]
                validated_output["recommendations"] = validated_output.get("recommended_next_steps", [])
                validated_output["limitations"] = validated_output.get("uncertainties", [])
        else:
            validation_status = ValidationStatus.failed
            validation_findings = [
                {"level": "L1", "code": "empty_output", "message": "LLM returned empty output", "severity": "error"}
            ]

    except OllamaUnavailableError as exc:
        logger.warning("ollama_unavailable", incident_id=incident_id, error=str(exc))
        validation_status = ValidationStatus.failed
        validation_findings = [
            {
                "level": "L1",
                "code": "ollama_unavailable",
                "message": str(exc),
                "severity": "error",
            }
        ]

    exp = await repo.create_explanation(
        incident_id=incident_id,
        model_id=settings.OLLAMA_MODEL,
        prompt_version=PROMPT_TEMPLATE_VERSION,
        raw_output=raw_output,
        validation_status=validation_status,
        validated_output=validated_output,
        validation_findings=validation_findings,
        llm_latency_ms=latency_ms,
    )

    vf = None
    if exp.validation_findings:
        try:
            vf = json.loads(exp.validation_findings)
        except (json.JSONDecodeError, TypeError):
            vf = None

    vo = None
    if exp.validated_output:
        try:
            vo = json.loads(exp.validated_output)
        except (json.JSONDecodeError, TypeError):
            vo = None

    return ExplanationResponse(
        explanation_id=exp.id,
        incident_id=exp.incident_id,
        model_id=exp.model_id,
        prompt_version=exp.prompt_version,
        validation_status=exp.validation_status.value
        if hasattr(exp.validation_status, "value")
        else str(exp.validation_status),
        validated_output=vo,
        validation_findings=vf,
        llm_latency_ms=exp.llm_latency_ms,
        created_at=exp.created_at,
    )


@router.post(
    "/{incident_id}/response-simulations",
    response_model=SimulationResponse,
    status_code=201,
)
async def create_response_simulation(
    incident_id: str,
    body: CreateSimulationRequest,
    db: DbDep,
) -> SimulationResponse:
    """
    Record a simulated response. No real network action is executed.
    """
    import json as _json

    audit = await record_simulation(
        incident_id=incident_id,
        proposed_action=body.proposed_action,
        action_target=body.action_target,
        action_scope=body.action_scope,
        actor=body.actor,
        db=db,
    )

    result_data = None
    if audit.result_json:
        try:
            result_data = _json.loads(audit.result_json)
        except (json.JSONDecodeError, TypeError):
            result_data = None

    sim_status = (
        audit.simulation_status.value
        if hasattr(audit.simulation_status, "value")
        else str(audit.simulation_status)
    )
    return SimulationResponse(
        simulation_id=audit.id,
        incident_id=audit.incident_id,
        proposed_action=audit.proposed_action,
        action_target=audit.action_target,
        action_scope=audit.action_scope,
        simulation_status=sim_status,
        simulated_only=audit.simulated_only,
        policy_decision=audit.policy_decision,
        actor=audit.actor,
        result_json=result_data,
        created_at=audit.created_at,
    )


@router.post("/{incident_id}/chat", response_model=IncidentChatResponse)
async def chat_with_incident_analyst(
    incident_id: str,
    body: IncidentChatRequest,
    db: DbDep,
) -> IncidentChatResponse:
    """
    Interactive SOC Analyst Assistant grounded strictly in this incident's evidence bundle.
    """
    import time
    import httpx
    from app.core.config import get_settings

    settings = get_settings()
    repo = ProvenanceRepository(db)
    incident = await repo.get_incident(incident_id)
    bundle = await build_evidence_bundle(incident_id, db)

    start_time = time.monotonic()
    user_query = body.message.strip()

    system_prompt = (
        "You are an expert SOC Incident Investigator assistant for the XAI-IDPS platform. "
        "An analyst is asking you a specific question about an intrusion detection incident.\n\n"
        "STRICT GROUNDING RULES:\n"
        "1. Answer ONLY using the facts from the incident evidence bundle below.\n"
        "2. Do NOT invent details, IP addresses, or CVEs not in the bundle.\n"
        "3. When referring to specific detections or evidence, cite their exact ID (e.g. det_..., ev_...).\n"
        "4. If asked about containment actions, state clearly that in this system ONLY SIMULATED actions are permitted.\n"
        "5. Be concise, direct, and professional (2-4 bullet points or short paragraphs).\n\n"
        f"INCIDENT EVIDENCE BUNDLE:\n{json.dumps(bundle, indent=2)}"
    )

    reply_text = ""
    citations: list[str] = []

    try:
        url = f"{settings.OLLAMA_BASE_URL}/api/chat"
        payload = {
            "model": settings.OLLAMA_MODEL,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_query},
            ],
            "stream": False,
            "options": {"temperature": 0.2, "num_predict": 512},
        }
        async with httpx.AsyncClient(timeout=25) as client:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
            reply_text = resp.json()["message"]["content"].strip()
    except Exception as exc:
        logger.warning("incident_chat_ollama_fallback", error=str(exc))
        # Deterministic fallback response grounded in evidence
        det_names = [d.get("detector_name") for d in bundle.get("detections", [])]
        reply_text = (
            f"Based on verified incident records for {incident_id} (Risk Score: {incident.risk_score}/100):\n\n"
            f"- **Constituent Findings:** {', '.join(det_names[:3]) or 'Statistical anomaly cluster'}\n"
            f"- **Correlation Basis:** {incident.correlation_reason or 'Temporal window entity match'}\n"
            f"- **Status:** {incident.status.value.upper()} (Severity: {incident.severity.value.upper()})\n"
            f"- **Guidance:** Review constituent packet offsets and run a simulated host containment to test isolation safely."
        )

    latency_ms = int((time.monotonic() - start_time) * 1000)

    # Extract cited IDs
    all_valid_ids = set(bundle.get("valid_detection_ids", []) + bundle.get("valid_evidence_ids", []))
    for cid in all_valid_ids:
        if cid in reply_text:
            citations.append(cid)

    return IncidentChatResponse(
        incident_id=incident_id,
        response=reply_text,
        citations=citations,
        latency_ms=latency_ms,
    )


@router.get("/{incident_id}/report")
async def get_incident_dossier_report(
    incident_id: str,
    db: DbDep,
) -> dict:
    """
    Generate an authoritative SOC forensic investigation report dossier.
    """
    from app.correlation.mitre_mapping import map_detections_to_mitre
    from app.reporting.dossier_generator import generate_incident_dossier

    repo = ProvenanceRepository(db)
    incident = await repo.get_incident(incident_id)

    detections = [link.detection for link in incident.detection_links]
    mitre_ttps = map_detections_to_mitre([
        {
            "detector_name": d.detector_name,
            "detector_type": d.detector_type.value if hasattr(d.detector_type, "value") else str(d.detector_type),
            "severity": d.severity,
            "raw_output_excerpt": d.raw_output_excerpt,
            "feature_snapshot": d.feature_snapshot,
        }
        for d in detections
    ])

    latest_exp = incident.explanations[-1] if incident.explanations else None
    simulations = incident.response_audits

    markdown_dossier = generate_incident_dossier(
        incident=incident,
        detections=detections,
        mitre_ttps=mitre_ttps,
        explanation=latest_exp,
        simulations=simulations,
    )

    return {
        "incident_id": incident_id,
        "filename": f"SOC_Dossier_{incident_id}.md",
        "content": markdown_dossier,
        "mitre_ttps": mitre_ttps,
    }

