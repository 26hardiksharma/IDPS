"""
Incident builder / correlation engine.
Groups related NormalizedDetections into Incidents using explicit,
versioned rules based on time windows and entity keys.

Correlation rules are conservative: a group of alerts is not proof of
a single attacker or attack.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from app.core.config import get_settings
from app.core.logging import get_logger
from app.detection.normalizer import NormalizedDetection

logger = get_logger(__name__)

CORRELATION_POLICY_VERSION = "1.0"


@dataclass
class DetectionGroup:
    """Intermediate correlation group before becoming an Incident record."""
    detections: list[NormalizedDetection] = field(default_factory=list)
    group_key: str = ""
    correlation_reason: str = ""
    first_seen: str | None = None
    last_seen: str | None = None


def correlate_detections(
    detections: list[NormalizedDetection],
    time_window_seconds: int | None = None,
    policy_version: str = CORRELATION_POLICY_VERSION,
) -> list[DetectionGroup]:
    """
    Group *detections* into correlation groups using:
      - shared src_ip (entity key)
      - overlapping time window (configurable, default from Settings)
      - same run (all detections passed in are for one run)

    Returns a list of DetectionGroup objects (one per incident candidate).
    A detection with no src_ip gets its own group.
    """
    settings = get_settings()
    window = time_window_seconds or settings.CORRELATION_TIME_WINDOW_SECONDS

    # Group by src_ip first
    by_src: dict[str, list[NormalizedDetection]] = defaultdict(list)
    for det in detections:
        key = det.src_ip or f"unknown_{id(det)}"
        by_src[key].append(det)

    groups: list[DetectionGroup] = []

    for src_ip, dets in by_src.items():
        # Sort by event_time (treat None as 0)
        try:
            dets_sorted = sorted(
                dets, key=lambda d: float(d.event_time) if d.event_time else 0.0
            )
        except (ValueError, TypeError):
            dets_sorted = dets

        # Sliding-window grouping
        current_group: list[NormalizedDetection] = []
        window_open_time: float | None = None

        for det in dets_sorted:
            try:
                t = float(det.event_time) if det.event_time else 0.0
            except (ValueError, TypeError):
                t = 0.0

            if window_open_time is None:
                window_open_time = t
                current_group = [det]
            elif t - window_open_time <= window:
                current_group.append(det)
            else:
                if current_group:
                    groups.append(
                        _make_group(src_ip, current_group, policy_version)
                    )
                current_group = [det]
                window_open_time = t

        if current_group:
            groups.append(_make_group(src_ip, current_group, policy_version))

    logger.info(
        "correlation_complete",
        input_detections=len(detections),
        output_groups=len(groups),
    )
    return groups


def _make_group(
    src_ip: str,
    dets: list[NormalizedDetection],
    policy_version: str,
) -> DetectionGroup:
    detector_types = {d.detector_type for d in dets}
    has_signature = "signature" in detector_types
    has_anomaly = "anomaly" in detector_types

    if has_signature and has_anomaly:
        reason = (
            f"Hybrid corroboration: {len(dets)} detections from src={src_ip} "
            f"within time window (policy_version={policy_version})"
        )
    elif has_signature:
        reason = (
            f"Signature cluster: {len(dets)} alerts from src={src_ip} "
            f"(policy_version={policy_version})"
        )
    else:
        reason = (
            f"Anomaly cluster: {len(dets)} anomaly detections from src={src_ip} "
            f"(policy_version={policy_version})"
        )

    times = [d.event_time for d in dets if d.event_time]
    return DetectionGroup(
        detections=dets,
        group_key=src_ip,
        correlation_reason=reason,
        first_seen=min(times) if times else None,
        last_seen=max(times) if times else None,
    )
