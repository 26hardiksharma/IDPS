"""
Shared Pydantic schemas for API request/response bodies.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


# ── Common ────────────────────────────────────────────────────────────────────

class ErrorResponse(BaseModel):
    error_code: str
    message: str
    detail: Optional[str] = None


class PaginatedMeta(BaseModel):
    total: Optional[int] = None
    limit: int
    offset: int


# ── Analysis runs ─────────────────────────────────────────────────────────────

class CreateRunRequest(BaseModel):
    input_path: str = Field(..., description="Path to PCAP (relative to PCAP_ROOT)")
    scenario_id: Optional[str] = None
    run_profile: str = "default"
    detector_mode: str = Field(
        "hybrid",
        description="signature | anomaly | hybrid",
        pattern="^(signature|anomaly|hybrid)$",
    )


class RunSummaryResponse(BaseModel):
    run_id: str
    status: str
    input_path: str
    input_hash: str
    scenario_id: Optional[str]
    run_profile: str
    detector_mode: str
    snort_version: Optional[str]
    error_summary: Optional[str]
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    created_at: datetime


class ExecuteRunResponse(BaseModel):
    run_id: str
    status: str
    incidents_created: int
    detections: int
    snort_errors: list[str]
    anomaly_errors: list[str]


# ── Evidence ──────────────────────────────────────────────────────────────────

class EvidenceResponse(BaseModel):
    evidence_id: str
    run_id: str
    source_type: str
    event_time: Optional[str]
    src_ip: Optional[str]
    dst_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: Optional[str]
    content_hash: Optional[str]
    normalized_data: Optional[Any]
    created_at: datetime


# ── Incidents ─────────────────────────────────────────────────────────────────

class DetectionSummary(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    detection_id: str
    detector_type: str
    detector_name: str
    event_time: Optional[str]
    src_ip: Optional[str]
    dst_ip: Optional[str]
    severity: Optional[str]
    score: Optional[float]
    rule_version_id: Optional[str]
    model_version_id: Optional[str]


class IncidentSummaryResponse(BaseModel):
    incident_id: str
    run_id: str
    status: str
    severity: str
    risk_score: float
    first_seen: Optional[str]
    last_seen: Optional[str]
    policy_version_id: str
    detection_count: int
    explanation_status: Optional[str]
    created_at: datetime


class IncidentDetailResponse(BaseModel):
    incident_id: str
    run_id: str
    status: str
    severity: str
    risk_score: float
    score_factors: Optional[Any]
    correlation_reason: Optional[str]
    first_seen: Optional[str]
    last_seen: Optional[str]
    policy_version_id: str
    detections: list[DetectionSummary]
    mitre_attack: Optional[list[dict[str, Any]]] = None
    created_at: datetime
    updated_at: datetime


class UpdateIncidentStatusRequest(BaseModel):
    status: str = Field(
        ...,
        pattern="^(open|under_review|acknowledged|closed)$",
    )


# ── Explanations ──────────────────────────────────────────────────────────────

class ExplanationResponse(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    explanation_id: str
    incident_id: str
    model_id: str
    prompt_version: str
    validation_status: str
    validated_output: Optional[Any]
    validation_findings: Optional[Any]
    llm_latency_ms: Optional[int]
    created_at: datetime


# ── Rules ─────────────────────────────────────────────────────────────────────

class RuleVersionResponse(BaseModel):
    rule_version_id: str
    rule_id: str
    version: str
    sha256: str
    source: str
    status: str
    created_at: datetime


class RegisterCandidateRuleRequest(BaseModel):
    rule_id: str
    version: str
    content: str = Field(..., min_length=10)
    source: str = "local"
    test_result_ref: Optional[str] = None


# ── Response simulations ──────────────────────────────────────────────────────

class CreateSimulationRequest(BaseModel):
    proposed_action: str
    action_target: Optional[str] = None
    action_scope: Optional[str] = None
    actor: Optional[str] = None


class SimulationResponse(BaseModel):
    simulation_id: str
    incident_id: str
    proposed_action: str
    action_target: Optional[str] = None
    action_scope: Optional[str] = None
    simulation_status: str
    simulated_only: bool = True
    policy_decision: Optional[str] = None
    actor: Optional[str] = None
    result_json: Optional[Any] = None
    created_at: datetime


# ── Metrics ───────────────────────────────────────────────────────────────────

class MetricsSummaryResponse(BaseModel):
    total_runs: int
    completed_runs: int
    failed_runs: int
    total_incidents: int
    incidents_by_severity: dict[str, int]
    total_detections: int
    signature_detections: int
    anomaly_detections: int
    total_explanations: int
    valid_explanations: int
    invalid_explanations: int
    total_simulations: int


# ── Interactive AI Analyst & What-If Simulation ──────────────────────────────

class IncidentChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=1000)


class IncidentChatResponse(BaseModel):
    incident_id: str
    response: str
    citations: list[str] = Field(default_factory=list)
    latency_ms: int = 0


class WhatIfRequest(BaseModel):
    signature_weight: float = Field(default=40.0, ge=10.0, le=60.0)
    anomaly_weight: float = Field(default=30.0, ge=10.0, le=50.0)
    corroboration_bonus: float = Field(default=10.0, ge=0.0, le=20.0)
    critical_threshold: float = Field(default=75.0, ge=50.0, le=95.0)
    high_threshold: float = Field(default=50.0, ge=30.0, le=70.0)
    medium_threshold: float = Field(default=25.0, ge=10.0, le=45.0)


class WhatIfShiftItem(BaseModel):
    incident_id: str
    old_score: float
    new_score: float
    old_severity: str
    new_severity: str


class WhatIfResponse(BaseModel):
    total_evaluated: int
    before_distribution: dict[str, int]
    after_distribution: dict[str, int]
    score_shifts: list[WhatIfShiftItem]

