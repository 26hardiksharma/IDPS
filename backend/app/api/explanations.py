"""
Explanations API router — GET /api/explanations/{explanation_id}
"""
from __future__ import annotations

import json
from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas import ExplanationResponse
from app.db.session import get_db_session
from app.provenance.repository import ProvenanceRepository

router = APIRouter(prefix="/api/explanations", tags=["explanations"])

DbDep = Annotated[AsyncSession, Depends(get_db_session)]


@router.get("/{explanation_id}", response_model=ExplanationResponse)
async def get_explanation(explanation_id: str, db: DbDep) -> ExplanationResponse:
    """Return an explanation and its validation results."""
    repo = ProvenanceRepository(db)
    exp = await repo.get_explanation(explanation_id)

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
