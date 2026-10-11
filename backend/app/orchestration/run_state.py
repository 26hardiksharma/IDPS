"""
Run state machine — defines valid status transitions for AnalysisRun.
"""
from __future__ import annotations

from app.db.models import RunStatus

# Allowed next states from each current state
VALID_TRANSITIONS: dict[RunStatus, set[RunStatus]] = {
    RunStatus.queued: {RunStatus.running, RunStatus.cancelled, RunStatus.invalid_input},
    RunStatus.running: {RunStatus.completed, RunStatus.failed, RunStatus.cancelled},
    RunStatus.completed: set(),
    RunStatus.failed: set(),
    RunStatus.cancelled: set(),
    RunStatus.invalid_input: set(),
}


def can_transition(current: RunStatus, target: RunStatus) -> bool:
    return target in VALID_TRANSITIONS.get(current, set())


def assert_transition(current: RunStatus, target: RunStatus) -> None:
    if not can_transition(current, target):
        raise ValueError(
            f"Invalid run state transition: {current.value} → {target.value}"
        )
