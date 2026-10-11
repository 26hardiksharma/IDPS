"""
Response simulator — records proposed/approved simulated response actions.

Safety guarantee:
- simulated_only is ALWAYS set to True.
- No code path invokes iptables, nftables, Windows Firewall, cloud APIs,
  router APIs, or any control that modifies real traffic.
- Every audit entry is appended; existing entries are never edited.
"""
from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import SimulationError
from app.core.logging import get_logger
from app.db.models import ResponseAudit, SimulationStatus
from app.provenance.repository import ProvenanceRepository

logger = get_logger(__name__)

# Allowed simulation action types — must never include real enforcement
ALLOWED_ACTIONS = {
    "simulate_source_isolation",
    "simulate_block_src_ip",
    "simulate_rate_limit",
    "simulate_quarantine",
    "simulate_alert_escalation",
    "simulate_pcap_capture",
    "acknowledge",
    "mark_false_positive",
    "escalate_to_analyst",
}


async def record_simulation(
    incident_id: str,
    proposed_action: str,
    action_target: str | None,
    action_scope: str | None,
    actor: str | None,
    db: AsyncSession,
) -> ResponseAudit:
    """
    Record a simulated (non-executing) response action for *incident_id*.
    Raises SimulationError if the action is not in the allowed set or
    if it contains language suggesting a real action.
    """
    # Validate action type
    if proposed_action not in ALLOWED_ACTIONS:
        raise SimulationError(
            f"Action '{proposed_action}' is not in the permitted simulation set",
            detail=f"Allowed: {sorted(ALLOWED_ACTIONS)}",
        )

    # Safety check on target/scope (no real system identifiers beyond simulation)
    _check_no_real_commands(proposed_action, action_target, action_scope)

    repo = ProvenanceRepository(db)

    # Confirm incident exists
    incident = await repo.get_incident(incident_id)

    policy_decision = (
        f"Simulation policy v1.0: action '{proposed_action}' approved for "
        f"simulation only. No real network control was modified."
    )

    result: dict[str, Any] = {
        "simulated_only": True,
        "action": proposed_action,
        "target": action_target,
        "scope": action_scope,
        "outcome": "simulation_recorded",
        "note": "NO REAL NETWORK ACTION WAS EXECUTED.",
    }

    audit = await repo.create_response_audit(
        incident_id=incident_id,
        proposed_action=proposed_action,
        action_target=action_target,
        action_scope=action_scope,
        policy_decision=policy_decision,
        simulation_status=SimulationStatus.simulated.value,
        actor=actor,
        result_json=result,
    )

    logger.info(
        "response_simulation_recorded",
        incident_id=incident_id,
        action=proposed_action,
        simulated_only=True,
    )
    return audit


def _check_no_real_commands(
    action: str,
    target: str | None,
    scope: str | None,
) -> None:
    """Raise SimulationError if any argument looks like a real OS command."""
    dangerous_patterns = [
        "iptables",
        "nftables",
        "firewall-cmd",
        "ufw",
        "netsh",
        "route add",
        "route delete",
        "ip route",
        "sudo",
        "PowerShell",
    ]
    combined = " ".join(filter(None, [action, target or "", scope or ""])).lower()
    for pat in dangerous_patterns:
        if pat.lower() in combined:
            raise SimulationError(
                f"Simulation target/scope contains a real enforcement pattern: '{pat}'",
                detail="Only simulated actions are permitted.",
            )
