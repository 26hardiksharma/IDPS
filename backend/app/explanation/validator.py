"""
Explanation validator — checks LLM output against stored evidence.

Validation levels:
  L1: Structural — valid JSON + required fields + allowed types
  L2: Reference integrity — every cited ID exists and belongs to this incident
  L3: Numeric/state consistency — numbers and response-state claims match DB
  L4: Claim support — rule-based checks (human review still required)
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError as PydanticValidationError

from app.explanation.schema import ExplanationOutput, ValidationStatus


@dataclass
class ValidatorFinding:
    level: str      # L1 | L2 | L3 | L4
    code: str
    message: str
    severity: str = "error"   # error | warning | info


@dataclass
class ValidationResult:
    status: ValidationStatus
    findings: list[ValidatorFinding] = field(default_factory=list)
    validated_output: ExplanationOutput | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "findings": [
                {
                    "level": f.level,
                    "code": f.code,
                    "message": f.message,
                    "severity": f.severity,
                }
                for f in self.findings
            ],
        }


def validate_explanation(
    raw_output: str,
    evidence_bundle: dict[str, Any],
) -> ValidationResult:
    """
    Run all validation levels against *raw_output* using *evidence_bundle*
    as the ground truth.
    """
    findings: list[ValidatorFinding] = []

    # ── L1: Structural validation ─────────────────────────────────────────────
    parsed = _validate_structure(raw_output, findings)
    if parsed is None:
        return ValidationResult(status=ValidationStatus.failed, findings=findings)

    # ── L2: Reference integrity ───────────────────────────────────────────────
    _validate_references(parsed, evidence_bundle, findings)

    # ── L3: Numeric/state consistency ────────────────────────────────────────
    _validate_consistency(parsed, evidence_bundle, findings)

    # ── L4: Claim support heuristics ─────────────────────────────────────────
    _validate_claim_support(parsed, findings)

    # Determine overall status
    errors = [f for f in findings if f.severity == "error"]
    warnings = [f for f in findings if f.severity == "warning"]

    if not errors and not warnings:
        status = ValidationStatus.valid
    elif errors:
        status = ValidationStatus.invalid
    else:
        status = ValidationStatus.partially_valid

    return ValidationResult(
        status=status,
        findings=findings,
        validated_output=parsed if status != ValidationStatus.invalid else None,
    )


def _validate_structure(
    raw: str, findings: list[ValidatorFinding]
) -> ExplanationOutput | None:
    """L1: Parse JSON and validate required schema fields."""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        findings.append(
            ValidatorFinding(
                level="L1",
                code="invalid_json",
                message=f"Output is not valid JSON: {exc}",
                severity="error",
            )
        )
        return None

    try:
        parsed = ExplanationOutput(**data)
        return parsed
    except PydanticValidationError as exc:
        for err in exc.errors():
            findings.append(
                ValidatorFinding(
                    level="L1",
                    code="schema_violation",
                    message=f"Field {'.'.join(str(x) for x in err['loc'])}: {err['msg']}",
                    severity="error",
                )
            )
        return None


def _validate_references(
    parsed: ExplanationOutput,
    bundle: dict[str, Any],
    findings: list[ValidatorFinding],
) -> None:
    """L2: Every cited ID must exist in the incident's evidence bundle."""
    valid_ids: set[str] = set()
    valid_ids.update(bundle.get("valid_evidence_ids", []))
    valid_ids.update(bundle.get("valid_detection_ids", []))
    valid_ids.update(bundle.get("valid_rule_version_ids", []))
    if bundle.get("incident_id"):
        valid_ids.add(bundle["incident_id"])
    if bundle.get("run_id"):
        valid_ids.add(bundle["run_id"])
    if bundle.get("policy_version_id"):
        valid_ids.add(bundle["policy_version_id"])

    # Check incident_id
    if parsed.incident_id != bundle.get("incident_id"):
        findings.append(
            ValidatorFinding(
                level="L2",
                code="incident_id_mismatch",
                message=(
                    f"Cited incident_id '{parsed.incident_id}' does not match "
                    f"expected '{bundle.get('incident_id')}'"
                ),
                severity="error",
            )
        )

    # Check all cited evidence_references
    for ref_id in parsed.evidence_references:
        if ref_id not in valid_ids:
            findings.append(
                ValidatorFinding(
                    level="L2",
                    code="invalid_evidence_reference",
                    message=f"Cited ID '{ref_id}' not found in incident scope",
                    severity="error",
                )
            )

    # Check IDs inside observation/interpretation lists
    for obs in parsed.observations:
        for eid in obs.evidence_ids:
            if eid not in valid_ids:
                findings.append(
                    ValidatorFinding(
                        level="L2",
                        code="invalid_observation_reference",
                        message=f"Observation cites '{eid}' which is not in scope",
                        severity="error",
                    )
                )

    for interp in parsed.interpretations:
        for eid in interp.evidence_ids:
            if eid not in valid_ids:
                findings.append(
                    ValidatorFinding(
                        level="L2",
                        code="invalid_interpretation_reference",
                        message=f"Interpretation cites '{eid}' which is not in scope",
                        severity="error",
                    )
                )


def _validate_consistency(
    parsed: ExplanationOutput,
    bundle: dict[str, Any],
    findings: list[ValidatorFinding],
) -> None:
    """L3: Check numeric claims and response-state consistency."""
    full_text = (
        parsed.summary
        + " ".join(o.claim for o in parsed.observations)
        + " ".join(i.claim for i in parsed.interpretations)
        + " ".join(parsed.recommended_next_steps)
    )

    # Check that no claim asserts a real block/firewall change occurred
    real_block_patterns = [
        r"\bfirewall rule\s+(was\s+)?added\b",
        r"\btraffic\s+(was\s+)?blocked\b",
        r"\bip\s+(was\s+)?banned\b",
        r"\biptables\b",
        r"\bnftables\b",
        r"\bnetwork\s+control\s+changed\b",
    ]
    for pat in real_block_patterns:
        if re.search(pat, full_text, re.IGNORECASE):
            findings.append(
                ValidatorFinding(
                    level="L3",
                    code="false_real_block_claim",
                    message=(
                        f"Explanation claims a real network action occurred "
                        f"(pattern: '{pat}'). Only simulated actions are possible."
                    ),
                    severity="error",
                )
            )

    # Check risk score if mentioned
    risk_score = bundle.get("risk_score")
    if risk_score is not None:
        # Strip IP addresses from summary before looking for numeric risk scores
        clean_summary = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "", parsed.summary)
        score_pattern = re.compile(r"\b(\d+(?:\.\d+)?)\b")
        for match in score_pattern.finditer(clean_summary):
            val = float(match.group(1))
            # Only flag large discrepancies (>5 points) to avoid false positives
            if 1 < val <= 100 and abs(val - risk_score) > 5:
                findings.append(
                    ValidatorFinding(
                        level="L3",
                        code="numeric_inconsistency",
                        message=(
                            f"Summary mentions value {val} but stored "
                            f"risk_score is {risk_score}"
                        ),
                        severity="warning",
                    )
                )


def _validate_claim_support(
    parsed: ExplanationOutput,
    findings: list[ValidatorFinding],
) -> None:
    """L4: Rule-based heuristic checks for clearly unsupported claims."""
    # Observations should have at least one evidence reference
    for i, obs in enumerate(parsed.observations):
        if not obs.evidence_ids:
            findings.append(
                ValidatorFinding(
                    level="L4",
                    code="observation_missing_citation",
                    message=f"Observation #{i} makes a claim without evidence references",
                    severity="warning",
                )
            )

    # Warn if summary is very short (less than 20 chars)
    if len(parsed.summary.strip()) < 20:
        findings.append(
            ValidatorFinding(
                level="L4",
                code="summary_too_short",
                message="Summary is too brief to be informative",
                severity="warning",
            )
        )
