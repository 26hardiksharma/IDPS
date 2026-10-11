"""
Runs API router — POST /api/runs, GET /api/runs/{run_id},
GET /api/runs/{run_id}/evidence, POST /api/runs/{run_id}/execute
"""
from __future__ import annotations

import json
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas import (
    CreateRunRequest,
    ErrorResponse,
    ExecuteRunResponse,
    EvidenceResponse,
    RunSummaryResponse,
)
from app.core.errors import ConflictError, InputRejectedError, NotFoundError
from app.db.session import get_db_session
from app.orchestration.run_service import create_run, execute_run
from app.provenance.repository import ProvenanceRepository

router = APIRouter(prefix="/api/runs", tags=["runs"])

DbDep = Annotated[AsyncSession, Depends(get_db_session)]


@router.post("", response_model=dict, status_code=201)
async def create_analysis_run(
    body: CreateRunRequest,
    db: DbDep,
) -> dict:
    """Create a queued analysis run for a permitted PCAP or scenario."""
    return await create_run(
        input_path_str=body.input_path,
        db=db,
        scenario_id=body.scenario_id,
        run_profile=body.run_profile,
        detector_mode=body.detector_mode,
    )


@router.post("/{run_id}/execute", response_model=ExecuteRunResponse)
async def execute_analysis_run(
    run_id: str,
    db: DbDep,
) -> ExecuteRunResponse:
    """Start or resume analysis for a queued run."""
    result = await execute_run(run_id, db)
    return ExecuteRunResponse(**result)


@router.get("/{run_id}", response_model=RunSummaryResponse)
async def get_run(run_id: str, db: DbDep) -> RunSummaryResponse:
    """Return run status and summary."""
    repo = ProvenanceRepository(db)
    run = await repo.get_run(run_id)
    return RunSummaryResponse(
        run_id=run.id,
        status=run.status.value,
        input_path=run.input_path,
        input_hash=run.input_hash,
        scenario_id=run.scenario_id,
        run_profile=run.run_profile,
        detector_mode=run.detector_mode,
        snort_version=run.snort_version,
        error_summary=run.error_summary,
        started_at=run.started_at,
        finished_at=run.finished_at,
        created_at=run.created_at,
    )


@router.get("", response_model=list[RunSummaryResponse])
async def list_runs(
    db: DbDep,
    limit: int = 50,
    offset: int = 0,
) -> list[RunSummaryResponse]:
    """List recent analysis runs."""
    repo = ProvenanceRepository(db)
    runs = await repo.list_runs(limit=limit, offset=offset)
    return [
        RunSummaryResponse(
            run_id=r.id,
            status=r.status.value,
            input_path=r.input_path,
            input_hash=r.input_hash,
            scenario_id=r.scenario_id,
            run_profile=r.run_profile,
            detector_mode=r.detector_mode,
            snort_version=r.snort_version,
            error_summary=r.error_summary,
            started_at=r.started_at,
            finished_at=r.finished_at,
            created_at=r.created_at,
        )
        for r in runs
    ]


@router.get("/{run_id}/evidence", response_model=list[EvidenceResponse])
async def list_evidence(
    run_id: str,
    db: DbDep,
    limit: int = 100,
    offset: int = 0,
) -> list[EvidenceResponse]:
    """List evidence records for a run (paginated)."""
    repo = ProvenanceRepository(db)
    # Confirm run exists
    await repo.get_run(run_id)
    evidence_list = await repo.list_evidence_for_run(run_id, limit=limit, offset=offset)
    result = []
    for ev in evidence_list:
        nd = None
        if ev.normalized_data:
            try:
                nd = json.loads(ev.normalized_data)
            except (json.JSONDecodeError, TypeError):
                nd = None
        result.append(
            EvidenceResponse(
                evidence_id=ev.id,
                run_id=ev.run_id,
                source_type=ev.source_type,
                event_time=ev.event_time,
                src_ip=ev.src_ip,
                dst_ip=ev.dst_ip,
                src_port=ev.src_port,
                dst_port=ev.dst_port,
                protocol=ev.protocol,
                content_hash=ev.content_hash,
                normalized_data=nd,
                created_at=ev.created_at,
            )
        )
    return result
