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


@router.get("/mitre")
async def get_mitre_metrics(db: DbDep) -> dict:
    """Return MITRE ATT&CK coverage and tactic distribution across all detections."""
    from app.correlation.mitre_mapping import map_detections_to_mitre, MITRE_TACTIC_ORDER

    dets_stmt = select(Detection).limit(200)
    dets = (await db.execute(dets_stmt)).scalars().all()

    det_dicts = [
        {
            "detector_name": d.detector_name,
            "detector_type": d.detector_type.value if hasattr(d.detector_type, "value") else str(d.detector_type),
            "severity": d.severity,
            "raw_output_excerpt": d.raw_output_excerpt,
            "feature_snapshot": d.feature_snapshot,
        }
        for d in dets
    ]
    ttps = map_detections_to_mitre(det_dicts)

    tactic_counts = {t: 0 for t in MITRE_TACTIC_ORDER}
    tech_counts: dict[str, dict[str, Any]] = {}

    for ttp in ttps:
        tac = ttp.get("tactic", "Discovery")
        tactic_counts[tac] = tactic_counts.get(tac, 0) + 1
        tid = ttp.get("technique_id", "T1046")
        if tid not in tech_counts:
            tech_counts[tid] = {
                "technique_id": tid,
                "technique_name": ttp.get("technique_name", "Unknown"),
                "tactic": tac,
                "count": 0,
            }
        tech_counts[tid]["count"] += 1

    top_techniques = sorted(tech_counts.values(), key=lambda x: x["count"], reverse=True)[:6]

    return {
        "total_ttps": len(ttps),
        "tactics": tactic_counts,
        "top_techniques": top_techniques,
        "active_tactics_count": sum(1 for v in tactic_counts.values() if v > 0),
    }


@router.post("/what-if")
async def simulate_what_if_policy(
    body: dict,
    db: DbDep,
) -> dict:
    """
    Recalculate risk scores dynamically across stored incidents under alternative policy weights.
    """
    import json as _json

    sig_w = float(body.get("signature_weight", 40.0))
    anom_w = float(body.get("anomaly_weight", 30.0))
    corrob_b = float(body.get("corroboration_bonus", 10.0))
    crit_th = float(body.get("critical_threshold", 75.0))
    high_th = float(body.get("high_threshold", 50.0))
    med_th = float(body.get("medium_threshold", 25.0))

    incs_stmt = select(Incident).order_by(Incident.created_at.desc()).limit(50)
    incs = (await db.execute(incs_stmt)).scalars().all()

    before_dist = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    after_dist = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    shifts: list[dict] = []

    for inc in incs:
        old_sev = inc.severity.value if hasattr(inc.severity, "value") else str(inc.severity)
        before_dist[old_sev] = before_dist.get(old_sev, 0) + 1

        factors = {}
        if inc.score_factors:
            try:
                factors = _json.loads(inc.score_factors)
            except Exception:
                factors = {}

        # Recompute score with new weights
        sig_f = factors.get("signature_signal", {})
        anom_f = factors.get("anomaly_band", {})
        rep_f = factors.get("repeated_behavior", {})
        corrob_f = factors.get("independent_corroboration", {})

        sig_raw = float(sig_f.get("raw_severity_score", 0.0) or 0.0)
        anom_raw = float(anom_f.get("max_score", 0.0) or 0.0)
        rep_contrib = float(rep_f.get("contribution", 0.0) or 0.0)

        # Scale contributions proportionally
        new_sig_contrib = min(sig_raw, sig_w)
        new_anom_contrib = min(anom_raw * anom_w, anom_w)
        new_corrob_contrib = corrob_b if corrob_f.get("has_both", False) or len(corrob_f.get("detector_types", [])) > 1 else 0.0

        new_score = round(min(100.0, new_sig_contrib + new_anom_contrib + rep_contrib + new_corrob_contrib), 2)
        if new_score == 0.0 and inc.risk_score > 0:
            # Fallback proportional re-scaling if factors were empty
            new_score = round(min(100.0, inc.risk_score * ((sig_w + anom_w) / 70.0)), 2)

        if new_score >= crit_th:
            new_sev = "critical"
        elif new_score >= high_th:
            new_sev = "high"
        elif new_score >= med_th:
            new_sev = "medium"
        else:
            new_sev = "low"

        after_dist[new_sev] = after_dist.get(new_sev, 0) + 1

        shifts.append({
            "incident_id": inc.id,
            "old_score": inc.risk_score,
            "new_score": new_score,
            "old_severity": old_sev,
            "new_severity": new_sev,
            "changed": old_sev != new_sev or abs(inc.risk_score - new_score) > 2.0,
        })

    return {
        "total_evaluated": len(incs),
        "before_distribution": before_dist,
        "after_distribution": after_dist,
        "score_shifts": shifts[:10],
    }

