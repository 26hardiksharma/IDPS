"""
Rules API router — GET /api/rules, POST /api/rules/candidates
"""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas import RegisterCandidateRuleRequest, RuleVersionResponse
from app.db.models import RuleStatus
from app.db.session import get_db_session
from app.provenance.version_registry import VersionRegistry

router = APIRouter(prefix="/api/rules", tags=["rules"])

DbDep = Annotated[AsyncSession, Depends(get_db_session)]


@router.get("", response_model=list[RuleVersionResponse])
async def list_rules(
    db: DbDep,
    include_candidates: bool = True,
) -> list[RuleVersionResponse]:
    """List configured rule versions (including candidates if requested)."""
    registry = VersionRegistry(db)
    rules = await registry.list_rule_versions(include_candidates=include_candidates)
    return [
        RuleVersionResponse(
            rule_version_id=r.id,
            rule_id=r.rule_id,
            version=r.version,
            sha256=r.sha256,
            source=r.source,
            status=r.status.value,
            created_at=r.created_at,
        )
        for r in rules
    ]


@router.post("/candidates", response_model=RuleVersionResponse, status_code=201)
async def register_candidate_rule(
    body: RegisterCandidateRuleRequest,
    db: DbDep,
) -> RuleVersionResponse:
    """
    Store a candidate rule version for review.
    Does NOT auto-deploy — stays in 'candidate' status until approved.
    """
    registry = VersionRegistry(db)
    rv = await registry.register_rule_version(
        rule_id=body.rule_id,
        version=body.version,
        content=body.content,
        source=body.source,
        test_result_ref=body.test_result_ref,
        status=RuleStatus.candidate,
    )
    return RuleVersionResponse(
        rule_version_id=rv.id,
        rule_id=rv.rule_id,
        version=rv.version,
        sha256=rv.sha256,
        source=rv.source,
        status=rv.status.value,
        created_at=rv.created_at,
    )
