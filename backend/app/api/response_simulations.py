"""
Response simulations API router (standalone) — for direct access to simulation audits.
Primary simulation creation is via POST /api/incidents/{id}/response-simulations.
"""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import ResponseAudit
from app.db.session import get_db_session

router = APIRouter(prefix="/api/response-simulations", tags=["response_simulations"])

DbDep = Annotated[AsyncSession, Depends(get_db_session)]


@router.get("", response_model=list[dict])
async def list_simulations(
    db: DbDep,
    incident_id: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[dict]:
    """List response simulation audit records."""
    import json

    stmt = (
        select(ResponseAudit)
        .order_by(ResponseAudit.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    if incident_id:
        stmt = stmt.where(ResponseAudit.incident_id == incident_id)

    rows = (await db.execute(stmt)).scalars().all()
    result = []
    for r in rows:
        result_data = None
        if r.result_json:
            try:
                result_data = json.loads(r.result_json)
            except (json.JSONDecodeError, TypeError):
                result_data = None
        result.append(
            {
                "simulation_id": r.id,
                "incident_id": r.incident_id,
                "proposed_action": r.proposed_action,
                "action_target": r.action_target,
                "action_scope": r.action_scope,
                "simulation_status": r.simulation_status.value,
                "simulated_only": r.simulated_only,  # Always True
                "policy_decision": r.policy_decision,
                "actor": r.actor,
                "result_json": result_data,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
        )
    return result
