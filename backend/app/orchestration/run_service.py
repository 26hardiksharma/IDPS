"""
Run service / orchestrator — coordinates the full analysis pipeline:
  1. Input validation
  2. Signature detection (Snort)
  3. Feature extraction + anomaly detection
  4. Output normalization
  5. Correlation + incident creation
  6. Deterministic risk scoring
  7. Provenance persistence

Detection must continue even if one path fails.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.errors import ConflictError, InputRejectedError, SnortError, AnomalyError
from app.core.logging import get_logger
from app.correlation.incident_builder import correlate_detections
from app.correlation.risk_scoring import compute_risk_score, get_scoring_config, SCORING_POLICY_VERSION
from app.db.models import RunStatus
from app.detection.anomaly_detector import (
    score_features,
    threshold_config_dict,
    MODEL_NAME as ANOMALY_MODEL_NAME,
    MODEL_VERSION as ANOMALY_MODEL_VERSION,
    FEATURE_SCHEMA_VERSION,
)
from app.detection.feature_extractor import extract_features
from app.detection.normalizer import (
    NormalizedDetection,
    normalize_anomaly_result,
    normalize_snort_alert,
)
from app.detection.snort_runner import get_snort_version, is_snort_available, run_snort
from app.orchestration.run_state import assert_transition
from app.provenance.hashing import hash_file
from app.provenance.id_factory import new_id
from app.provenance.repository import ProvenanceRepository
from app.provenance.version_registry import VersionRegistry

logger = get_logger(__name__)


async def create_run(
    input_path_str: str,
    db: AsyncSession,
    scenario_id: str | None = None,
    run_profile: str = "default",
    detector_mode: str = "hybrid",
) -> dict[str, Any]:
    """
    Validate input and create a queued AnalysisRun.
    Returns the new run's id and status.
    """
    settings = get_settings()
    input_path = Path(input_path_str)
    if not input_path.exists() and not input_path.is_absolute():
        candidate = settings.PCAP_ROOT / input_path
        if candidate.exists():
            input_path = candidate

    # ── Input validation ──────────────────────────────────────────────────────
    if not input_path.exists():
        raise InputRejectedError(f"PCAP not found: {input_path.name}")

    if not input_path.is_file():
        raise InputRejectedError("Input must be a regular file")

    # Path traversal guard: must be under configured PCAP_ROOT
    try:
        input_path.resolve().relative_to(settings.PCAP_ROOT.resolve())
    except ValueError:
        raise InputRejectedError(
            "Input file must be inside the configured PCAP root directory",
            detail=f"PCAP_ROOT={settings.PCAP_ROOT}",
        )

    size = input_path.stat().st_size
    if size > settings.max_pcap_bytes:
        raise InputRejectedError(
            f"File too large: {size} bytes (max {settings.MAX_PCAP_MB} MB)"
        )

    # Magic bytes check — PCAP files start with 0xd4c3b2a1 or 0xa1b2c3d4
    with input_path.open("rb") as fh:
        magic = fh.read(4)
    if magic not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a"):
        raise InputRejectedError("File does not appear to be a valid PCAP/PCAPNG")

    input_hash = hash_file(input_path)

    repo = ProvenanceRepository(db)
    run = await repo.create_run(
        input_path=str(input_path),
        input_hash=input_hash,
        scenario_id=scenario_id,
        run_profile=run_profile,
        detector_mode=detector_mode,
    )
    await repo.log_event(
        component="run_service",
        event_type="run_created",
        status="ok",
        run_id=run.id,
        message=f"Input={input_path.name} hash={input_hash[:12]}…",
    )
    return {"run_id": run.id, "status": run.status.value}


async def execute_run(run_id: str, db: AsyncSession) -> dict[str, Any]:
    """
    Execute the full analysis pipeline for an existing queued run.
    Raises ConflictError if the run is already running/completed.
    """
    settings = get_settings()
    repo = ProvenanceRepository(db)
    registry = VersionRegistry(db)

    run = await repo.get_run(run_id)

    # Idempotency / conflict check
    if run.status == RunStatus.running:
        raise ConflictError(f"Run {run_id} is already running")
    if run.status in (RunStatus.completed, RunStatus.failed):
        raise ConflictError(
            f"Run {run_id} has already finished with status '{run.status.value}'. "
            "Create a new run to re-analyse."
        )

    assert_transition(run.status, RunStatus.running)
    run = await repo.update_run_status(run_id, RunStatus.running)

    pcap_path = Path(run.input_path)
    snort_errors: list[str] = []
    snort_skipped: bool = False  # True when Snort is simply not installed
    anomaly_errors: list[str] = []
    all_normalised: list[NormalizedDetection] = []

    # ── Register model version for anomaly detector ───────────────────────────
    threshold_cfg = threshold_config_dict(settings)
    model_ver = await registry.get_or_create_model_version(
        detector_type="threshold",
        model_name=ANOMALY_MODEL_NAME,
        version=ANOMALY_MODEL_VERSION,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        threshold_config=threshold_cfg,
    )
    await repo.update_run_status(run_id, RunStatus.running, anomaly_model_id=model_ver.id)

    # ── Path A: Snort signature detection ────────────────────────────────────
    if run.detector_mode in ("signature", "hybrid"):
        # Pre-flight: check if Snort is installed before attempting to run it
        snort_installed = await is_snort_available()
        if not snort_installed:
            msg = "Snort binary not found — signature detection skipped"
            logger.info("snort_not_installed", run_id=run_id)
            await repo.log_event(
                component="snort_runner",
                event_type="snort_skipped",
                status="info",
                run_id=run_id,
                message=msg,
            )
            if run.detector_mode == "signature":
                # Signature-only mode cannot proceed without Snort
                snort_errors.append(msg)
            else:
                # Hybrid mode: gracefully skip Snort, anomaly path continues
                snort_skipped = True
        else:
            try:
                snort_ver = await get_snort_version(settings.SNORT_BIN)
                snort_alerts = await run_snort(pcap_path, run_id)
                await repo.update_run_status(
                    run_id, RunStatus.running, snort_version=snort_ver
                )
                logger.info("snort_alerts", run_id=run_id, count=len(snort_alerts))

                for alert in snort_alerts:
                    # Create an evidence record for this alert
                    ev = await repo.create_evidence(
                        run_id=run_id,
                        source_type="snort_alert",
                        normalized_data=alert,
                        raw_reference=str(pcap_path),
                        event_time=alert.get("timestamp"),
                        src_ip=alert.get("src_addr"),
                        dst_ip=alert.get("dst_addr"),
                        src_port=alert.get("src_port"),
                        dst_port=alert.get("dst_port"),
                        protocol=str(alert.get("proto", "")).upper() or None,
                    )
                    nd = normalize_snort_alert(alert)

                    # Look up or register the rule version
                    rule_info = alert.get("rule", {}) or {}
                    sid = rule_info.get("sid")
                    rev = rule_info.get("rev", 0)
                    rule_ver = None
                    if sid:
                        gid = rule_info.get("gid", 1)
                        rule_content = f"gid={gid};sid={sid};rev={rev}"
                        rule_ver = await registry.register_rule_version(
                            rule_id=f"{gid}:{sid}",
                            version=str(rev),
                            content=rule_content,
                        )

                    det = await repo.create_detection(
                        run_id=run_id,
                        detector_type=nd.detector_type,
                        detector_name=nd.detector_name,
                        evidence_id=ev.id,
                        event_time=nd.event_time,
                        src_ip=nd.src_ip,
                        dst_ip=nd.dst_ip,
                        src_port=nd.src_port,
                        dst_port=nd.dst_port,
                        protocol=nd.protocol,
                        rule_version_id=rule_ver.id if rule_ver else None,
                        severity=nd.severity,
                        score=nd.score,
                        raw_output_excerpt=nd.raw_output_excerpt,
                    )
                    nd._detection_id = det.id  # type: ignore[attr-defined]
                    all_normalised.append(nd)

            except Exception as exc:
                snort_errors.append(str(exc))
                logger.error("snort_detection_failed", run_id=run_id, error=str(exc))
                await repo.log_event(
                    component="snort_runner",
                    event_type="detection_failed",
                    status="error",
                    run_id=run_id,
                    message=str(exc)[:500],
                )

    # ── Path B: Feature extraction + anomaly detection ────────────────────────
    if run.detector_mode in ("anomaly", "hybrid"):
        try:
            feature_records = extract_features(pcap_path)
            anomaly_results = score_features(feature_records, threshold_cfg)
            logger.info(
                "anomaly_results",
                run_id=run_id,
                features=len(feature_records),
                anomalous=sum(1 for r in anomaly_results if r.is_anomalous),
            )

            for result in anomaly_results:
                if not result.is_anomalous:
                    continue  # only persist actual detections

                ev = await repo.create_evidence(
                    run_id=run_id,
                    source_type="anomaly_feature",
                    normalized_data=result.feature_snapshot,
                    event_time=str(result.window_start),
                    src_ip=result.src_ip,
                )
                nd = normalize_anomaly_result(result)

                det = await repo.create_detection(
                    run_id=run_id,
                    detector_type=nd.detector_type,
                    detector_name=nd.detector_name,
                    evidence_id=ev.id,
                    event_time=nd.event_time,
                    src_ip=nd.src_ip,
                    model_version_id=model_ver.id,
                    severity=nd.severity,
                    score=nd.score,
                    feature_snapshot=result.feature_snapshot,
                    raw_output_excerpt=nd.raw_output_excerpt,
                )
                nd._detection_id = det.id  # type: ignore[attr-defined]
                all_normalised.append(nd)

        except Exception as exc:
            anomaly_errors.append(str(exc))
            logger.error("anomaly_detection_failed", run_id=run_id, error=str(exc))
            await repo.log_event(
                component="anomaly_detector",
                event_type="detection_failed",
                status="error",
                run_id=run_id,
                message=str(exc)[:500],
            )

    # ── Correlation + risk scoring ────────────────────────────────────────────
    groups = correlate_detections(all_normalised)

    # Get/create policy version
    scoring_cfg = get_scoring_config()
    policy_ver = await registry.get_or_create_policy_version(
        policy_type="correlation_and_scoring",
        version=SCORING_POLICY_VERSION,
        correlation_config={"time_window_seconds": settings.CORRELATION_TIME_WINDOW_SECONDS},
        scoring_config=scoring_cfg,
    )

    for group in groups:
        risk = compute_risk_score(group.detections)
        incident = await repo.create_incident(
            run_id=run_id,
            policy_version_id=policy_ver.id,
            severity=risk.severity,
            risk_score=risk.risk_score,
            score_factors=risk.factors,
            correlation_reason=group.correlation_reason,
            first_seen=group.first_seen,
            last_seen=group.last_seen,
        )
        # Link detections to incident using stored IDs
        for nd in group.detections:
            det_id = getattr(nd, "_detection_id", None)
            if det_id:
                await repo.link_detection_to_incident(
                    incident_id=incident.id,
                    detection_id=det_id,
                    correlation_reason=group.correlation_reason,
                )

    # ── Finalise run status ───────────────────────────────────────────────────
    if run.detector_mode == "signature" and snort_errors:
        final_status = RunStatus.failed
        error_summary = "; ".join(snort_errors)
    elif run.detector_mode == "anomaly" and anomaly_errors:
        final_status = RunStatus.failed
        error_summary = "; ".join(anomaly_errors)
    elif snort_errors and anomaly_errors:
        # Both paths failed in hybrid mode
        final_status = RunStatus.failed
        error_summary = "; ".join(snort_errors + anomaly_errors)
    elif snort_errors or anomaly_errors:
        # Partial success in hybrid mode
        final_status = RunStatus.completed
        error_summary = "Partial failure: " + "; ".join(snort_errors + anomaly_errors)
    elif snort_skipped:
        # Hybrid mode but Snort not installed — anomaly-only is fine
        final_status = RunStatus.completed
        error_summary = None
    else:
        final_status = RunStatus.completed
        error_summary = None

    await repo.update_run_status(
        run_id,
        final_status,
        error_summary=error_summary,
    )

    return {
        "run_id": run_id,
        "status": final_status.value,
        "incidents_created": len(groups),
        "detections": len(all_normalised),
        "snort_errors": snort_errors,
        "anomaly_errors": anomaly_errors,
    }
