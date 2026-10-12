"""
Provenance repository — persistence helpers for runs, evidence, detections,
incidents, and audit records.
Business logic stays in service modules; this layer only handles I/O.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.errors import NotFoundError
from app.db.models import (
    AnalysisRun,
    Detection,
    Evidence,
    EventLog,
    Explanation,
    ExplanationCitation,
    Incident,
    IncidentDetection,
    IncidentStatus,
    ResponseAudit,
    RunStatus,
    SimulationStatus,
)
from app.provenance.id_factory import new_id


class ProvenanceRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._db = session

    # ── Analysis runs ─────────────────────────────────────────────────────────

    async def create_run(
        self,
        input_path: str,
        input_hash: str,
        scenario_id: str | None,
        run_profile: str,
        detector_mode: str,
    ) -> AnalysisRun:
        run = AnalysisRun(
            id=new_id("run"),
            input_path=input_path,
            input_hash=input_hash,
            scenario_id=scenario_id,
            run_profile=run_profile,
            detector_mode=detector_mode,
            status=RunStatus.queued,
        )
        self._db.add(run)
        await self._db.flush()
        return run

    async def get_run(self, run_id: str) -> AnalysisRun:
        row = await self._db.get(AnalysisRun, run_id)
        if row is None:
            raise NotFoundError(f"Run {run_id} not found")
        return row

    async def list_runs(self, limit: int = 50, offset: int = 0) -> Sequence[AnalysisRun]:
        stmt = (
            select(AnalysisRun)
            .order_by(AnalysisRun.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        result = await self._db.execute(stmt)
        return result.scalars().all()

    async def update_run_status(
        self,
        run_id: str,
        status: RunStatus,
        error_summary: str | None = None,
        snort_version: str | None = None,
        snort_config_hash: str | None = None,
        ruleset_version_hash: str | None = None,
        anomaly_model_id: str | None = None,
    ) -> AnalysisRun:
        run = await self.get_run(run_id)
        run.status = status
        if error_summary is not None:
            run.error_summary = error_summary
        if status == RunStatus.running and run.started_at is None:
            run.started_at = datetime.now(timezone.utc).replace(tzinfo=None)
        if status in (RunStatus.completed, RunStatus.failed, RunStatus.cancelled):
            run.finished_at = datetime.now(timezone.utc).replace(tzinfo=None)
        if snort_version:
            run.snort_version = snort_version
        if snort_config_hash:
            run.snort_config_hash = snort_config_hash
        if ruleset_version_hash:
            run.ruleset_version_hash = ruleset_version_hash
        if anomaly_model_id:
            run.anomaly_model_id = anomaly_model_id
        await self._db.flush()
        return run

    # ── Evidence ──────────────────────────────────────────────────────────────

    async def create_evidence(
        self,
        run_id: str,
        source_type: str,
        normalized_data: dict | None = None,
        raw_reference: str | None = None,
        capture_offset: str | None = None,
        event_time: str | None = None,
        src_ip: str | None = None,
        dst_ip: str | None = None,
        src_port: int | None = None,
        dst_port: int | None = None,
        protocol: str | None = None,
        content_hash: str | None = None,
    ) -> Evidence:
        ev = Evidence(
            id=new_id("ev"),
            run_id=run_id,
            source_type=source_type,
            capture_offset=capture_offset,
            event_time=event_time,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            normalized_data=json.dumps(normalized_data) if normalized_data else None,
            raw_reference=raw_reference,
            content_hash=content_hash,
        )
        self._db.add(ev)
        await self._db.flush()
        return ev

    async def list_evidence_for_run(
        self,
        run_id: str,
        limit: int = 100,
        offset: int = 0,
    ) -> Sequence[Evidence]:
        stmt = (
            select(Evidence)
            .where(Evidence.run_id == run_id)
            .order_by(Evidence.created_at)
            .limit(limit)
            .offset(offset)
        )
        result = await self._db.execute(stmt)
        return result.scalars().all()

    # ── Detections ────────────────────────────────────────────────────────────

    async def create_detection(
        self,
        run_id: str,
        detector_type: str,
        detector_name: str,
        evidence_id: str | None = None,
        event_time: str | None = None,
        src_ip: str | None = None,
        dst_ip: str | None = None,
        src_port: int | None = None,
        dst_port: int | None = None,
        protocol: str | None = None,
        rule_version_id: str | None = None,
        model_version_id: str | None = None,
        severity: str | None = None,
        score: float | None = None,
        feature_snapshot: dict | None = None,
        raw_output_excerpt: str | None = None,
        normalizer_version: str = "1.0",
    ) -> Detection:
        det = Detection(
            id=new_id("det"),
            run_id=run_id,
            evidence_id=evidence_id,
            detector_type=detector_type,
            detector_name=detector_name,
            event_time=event_time,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            rule_version_id=rule_version_id,
            model_version_id=model_version_id,
            severity=severity,
            score=score,
            feature_snapshot=json.dumps(feature_snapshot) if feature_snapshot else None,
            raw_output_excerpt=raw_output_excerpt,
            normalizer_version=normalizer_version,
        )
        self._db.add(det)
        await self._db.flush()
        return det

    async def list_detections_for_run(self, run_id: str) -> Sequence[Detection]:
        stmt = select(Detection).where(Detection.run_id == run_id).order_by(Detection.created_at)
        result = await self._db.execute(stmt)
        return result.scalars().all()

    # ── Incidents ─────────────────────────────────────────────────────────────

    async def create_incident(
        self,
        run_id: str,
        policy_version_id: str,
        severity: str,
        risk_score: float,
        score_factors: dict | None = None,
        correlation_reason: str | None = None,
        first_seen: str | None = None,
        last_seen: str | None = None,
    ) -> Incident:
        inc = Incident(
            id=new_id("inc"),
            run_id=run_id,
            policy_version_id=policy_version_id,
            severity=severity,
            risk_score=risk_score,
            score_factors=json.dumps(score_factors) if score_factors else None,
            correlation_reason=correlation_reason,
            first_seen=first_seen,
            last_seen=last_seen,
        )
        self._db.add(inc)
        await self._db.flush()
        return inc

    async def link_detection_to_incident(
        self,
        incident_id: str,
        detection_id: str,
        correlation_reason: str | None = None,
    ) -> IncidentDetection:
        link = IncidentDetection(
            incident_id=incident_id,
            detection_id=detection_id,
            correlation_reason=correlation_reason,
        )
        self._db.add(link)
        await self._db.flush()
        return link

    async def get_incident(self, incident_id: str) -> Incident:
        stmt = (
            select(Incident)
            .options(
                selectinload(Incident.detection_links).selectinload(
                    IncidentDetection.detection
                ),
                selectinload(Incident.explanations),
                selectinload(Incident.response_audits),
                selectinload(Incident.policy_version),
            )
            .where(Incident.id == incident_id)
        )
        row = (await self._db.execute(stmt)).scalar_one_or_none()
        if row is None:
            raise NotFoundError(f"Incident {incident_id} not found")
        return row

    async def list_incidents(
        self,
        run_id: str | None = None,
        severity: str | None = None,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Sequence[Incident]:
        stmt = (
            select(Incident)
            .options(
                selectinload(Incident.detection_links),
                selectinload(Incident.explanations),
            )
            .order_by(Incident.created_at.desc())
        )
        if run_id:
            stmt = stmt.where(Incident.run_id == run_id)
        if severity:
            stmt = stmt.where(Incident.severity == severity)
        if status:
            stmt = stmt.where(Incident.status == status)
        stmt = stmt.limit(limit).offset(offset)
        result = await self._db.execute(stmt)
        return result.scalars().all()

    async def update_incident_status(
        self, incident_id: str, status: str | IncidentStatus
    ) -> Incident:
        inc = await self.get_incident(incident_id)
        if isinstance(status, str):
            status = IncidentStatus(status)
        inc.status = status
        await self._db.flush()
        return inc

    # ── Explanations ──────────────────────────────────────────────────────────

    async def create_explanation(
        self,
        incident_id: str,
        model_id: str,
        prompt_version: str,
        raw_output: str | None,
        validation_status: str,
        validated_output: dict | None = None,
        validation_findings: list | None = None,
        llm_latency_ms: int | None = None,
    ) -> Explanation:
        exp = Explanation(
            id=new_id("exp"),
            incident_id=incident_id,
            model_id=model_id,
            prompt_version=prompt_version,
            raw_output=raw_output,
            validation_status=validation_status,
            validated_output=json.dumps(validated_output) if validated_output else None,
            validation_findings=json.dumps(validation_findings) if validation_findings else None,
            llm_latency_ms=llm_latency_ms,
        )
        self._db.add(exp)
        await self._db.flush()
        return exp

    async def get_explanation(self, explanation_id: str) -> Explanation:
        stmt = (
            select(Explanation)
            .options(selectinload(Explanation.citations))
            .where(Explanation.id == explanation_id)
        )
        row = (await self._db.execute(stmt)).scalar_one_or_none()
        if row is None:
            raise NotFoundError(f"Explanation {explanation_id} not found")
        return row

    async def add_citation(
        self,
        explanation_id: str,
        record_type: str,
        record_id: str,
        evidence_id: str | None = None,
        claim_id: str | None = None,
    ) -> ExplanationCitation:
        cit = ExplanationCitation(
            explanation_id=explanation_id,
            evidence_id=evidence_id,
            record_type=record_type,
            record_id=record_id,
            claim_id=claim_id,
        )
        self._db.add(cit)
        await self._db.flush()
        return cit

    # ── Response audit ────────────────────────────────────────────────────────

    async def create_response_audit(
        self,
        incident_id: str,
        proposed_action: str,
        action_target: str | None = None,
        action_scope: str | None = None,
        policy_decision: str | None = None,
        simulation_status: str = "proposed",
        actor: str | None = None,
        result_json: dict | None = None,
    ) -> ResponseAudit:
        if isinstance(simulation_status, str):
            try:
                simulation_status = SimulationStatus(simulation_status)
            except ValueError:
                pass
        audit = ResponseAudit(
            id=new_id("audt"),
            incident_id=incident_id,
            proposed_action=proposed_action,
            action_target=action_target,
            action_scope=action_scope,
            policy_decision=policy_decision,
            simulation_status=simulation_status,
            simulated_only=True,  # ALWAYS true — safety constraint
            actor=actor,
            result_json=json.dumps(result_json) if result_json else None,
        )
        self._db.add(audit)
        await self._db.flush()
        return audit

    # ── Event log ─────────────────────────────────────────────────────────────

    async def log_event(
        self,
        component: str,
        event_type: str,
        status: str,
        message: str | None = None,
        run_id: str | None = None,
        incident_id: str | None = None,
        duration_ms: int | None = None,
    ) -> None:
        entry = EventLog(
            run_id=run_id,
            incident_id=incident_id,
            component=component,
            event_type=event_type,
            status=status,
            message=message,
            duration_ms=duration_ms,
        )
        self._db.add(entry)
        await self._db.flush()
