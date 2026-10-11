"""
Metrics API router — GET /api/metrics
Returns evaluation and run-level metrics from the provenance store.
"""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas import MetricsSummaryResponse
from app.db.models import (
    AnalysisRun,
    Detection,
    DetectorType,
    Explanation,
    Incident,
    ResponseAudit,
    RunStatus,
    ValidationStatus,
)
from app.db.session import get_db_session

router = APIRouter(prefix="/api/metrics", tags=["metrics"])

DbDep = Annotated[AsyncSession, Depends(get_db_session)]


@router.get("", response_model=MetricsSummaryResponse)
async def get_metrics(db: DbDep) -> MetricsSummaryResponse:
    """Return evaluation and run metrics from the database."""

    # Run counts
    total_runs = (await db.execute(select(func.count(AnalysisRun.id)))).scalar_one()
    completed_runs = (
        await db.execute(
            select(func.count(AnalysisRun.id)).where(AnalysisRun.status == RunStatus.completed)
        )
    ).scalar_one()
    failed_runs = (
        await db.execute(
            select(func.count(AnalysisRun.id)).where(AnalysisRun.status == RunStatus.failed)
        )
    ).scalar_one()

    # Incident counts
    total_incidents = (await db.execute(select(func.count(Incident.id)))).scalar_one()

    # Incidents by severity
    severity_counts: dict[str, int] = {}
    rows = (
        await db.execute(
            select(Incident.severity, func.count(Incident.id)).group_by(Incident.severity)
        )
    ).all()
    for row in rows:
        sev = row[0].value if hasattr(row[0], "value") else str(row[0])
        severity_counts[sev] = row[1]

    # Detection counts
    total_detections = (await db.execute(select(func.count(Detection.id)))).scalar_one()
    sig_dets = (
        await db.execute(
            select(func.count(Detection.id)).where(
                Detection.detector_type == DetectorType.signature
            )
        )
    ).scalar_one()
    anom_dets = (
        await db.execute(
            select(func.count(Detection.id)).where(
                Detection.detector_type == DetectorType.anomaly
            )
        )
    ).scalar_one()

    # Explanation counts
    total_explanations = (await db.execute(select(func.count(Explanation.id)))).scalar_one()
    valid_explanations = (
        await db.execute(
            select(func.count(Explanation.id)).where(
                Explanation.validation_status == ValidationStatus.valid
            )
        )
    ).scalar_one()
    invalid_explanations = (
        await db.execute(
            select(func.count(Explanation.id)).where(
                Explanation.validation_status == ValidationStatus.invalid
            )
        )
    ).scalar_one()

    # Simulation count
    total_simulations = (await db.execute(select(func.count(ResponseAudit.id)))).scalar_one()

    return MetricsSummaryResponse(
        total_runs=total_runs,
        completed_runs=completed_runs,
        failed_runs=failed_runs,
        total_incidents=total_incidents,
        incidents_by_severity=severity_counts,
        total_detections=total_detections,
        signature_detections=sig_dets,
        anomaly_detections=anom_dets,
        total_explanations=total_explanations,
        valid_explanations=valid_explanations,
        invalid_explanations=invalid_explanations,
        total_simulations=total_simulations,
    )
