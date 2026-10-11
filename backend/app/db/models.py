"""
SQLAlchemy ORM models for the XAI-IDPS provenance store.
All tables use SQLite via async aiosqlite engine.
"""
from __future__ import annotations

import enum
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


# ── Enumerations ──────────────────────────────────────────────────────────────

class RunStatus(str, enum.Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"
    invalid_input = "invalid_input"


class DetectorType(str, enum.Enum):
    signature = "signature"
    anomaly = "anomaly"


class IncidentStatus(str, enum.Enum):
    open = "open"
    under_review = "under_review"
    acknowledged = "acknowledged"
    closed = "closed"


class SeverityBand(str, enum.Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class ValidationStatus(str, enum.Enum):
    pending = "pending"
    valid = "valid"
    partially_valid = "partially_valid"
    invalid = "invalid"
    failed = "failed"


class RuleStatus(str, enum.Enum):
    candidate = "candidate"
    active = "active"
    deprecated = "deprecated"


class SimulationStatus(str, enum.Enum):
    proposed = "proposed"
    approved = "approved"
    rejected = "rejected"
    simulated = "simulated"


# ── Tables ────────────────────────────────────────────────────────────────────

class AnalysisRun(Base):
    """Represents one analysis job over a PCAP file or lab scenario."""
    __tablename__ = "analysis_runs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    input_path: Mapped[str] = mapped_column(String(512))
    input_hash: Mapped[str] = mapped_column(String(128))
    scenario_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    run_profile: Mapped[str] = mapped_column(String(64), default="default")
    status: Mapped[RunStatus] = mapped_column(
        Enum(RunStatus), default=RunStatus.queued
    )
    # Detector mode: signature, anomaly, or hybrid
    detector_mode: Mapped[str] = mapped_column(String(32), default="hybrid")
    snort_version: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    snort_config_hash: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    ruleset_version_hash: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    anomaly_model_id: Mapped[Optional[str]] = mapped_column(
        String(64), ForeignKey("model_versions.id"), nullable=True
    )
    error_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), nullable=False
    )

    # Relationships
    evidence: Mapped[list["Evidence"]] = relationship(
        back_populates="run", cascade="all, delete-orphan"
    )
    detections: Mapped[list["Detection"]] = relationship(
        back_populates="run", cascade="all, delete-orphan"
    )
    incidents: Mapped[list["Incident"]] = relationship(
        back_populates="run", cascade="all, delete-orphan"
    )


class Evidence(Base):
    """A bounded packet/flow/log excerpt or derived feature record."""
    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    run_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("analysis_runs.id"), nullable=False
    )
    source_type: Mapped[str] = mapped_column(String(64))  # e.g. pcap_packet, flow, dns_query
    capture_offset: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    event_time: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    src_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    dst_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    src_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    protocol: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    # JSON-serialised bounded payload/feature snapshot (not full raw PCAP)
    normalized_data: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    raw_reference: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    content_hash: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())

    run: Mapped["AnalysisRun"] = relationship(back_populates="evidence")
    detections: Mapped[list["Detection"]] = relationship(back_populates="evidence")
    citations: Mapped[list["ExplanationCitation"]] = relationship(
        back_populates="evidence"
    )


class RuleVersion(Base):
    """Immutable snapshot of a Snort rule at a point in time."""
    __tablename__ = "rule_versions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(128), nullable=False)  # stable rule identifier
    version: Mapped[str] = mapped_column(String(32), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    sha256: Mapped[str] = mapped_column(String(128), nullable=False)
    source: Mapped[str] = mapped_column(String(256), default="local")
    status: Mapped[RuleStatus] = mapped_column(
        Enum(RuleStatus), default=RuleStatus.candidate
    )
    test_result_ref: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())

    detections: Mapped[list["Detection"]] = relationship(back_populates="rule_version")

    __table_args__ = (
        UniqueConstraint("rule_id", "version", name="uq_rule_version"),
    )


class ModelVersion(Base):
    """Versioned snapshot of the anomaly model configuration."""
    __tablename__ = "model_versions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    detector_type: Mapped[str] = mapped_column(String(32))  # threshold | isolation_forest
    model_name: Mapped[str] = mapped_column(String(128))
    version: Mapped[str] = mapped_column(String(32))
    feature_schema_version: Mapped[str] = mapped_column(String(32))
    artifact_hash: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    training_dataset_ref: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    # JSON-serialised threshold/config
    threshold_config: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())

    detections: Mapped[list["Detection"]] = relationship(back_populates="model_version")
    runs: Mapped[list["AnalysisRun"]] = relationship(back_populates="anomaly_model")


class PolicyVersion(Base):
    """Versioned correlation and risk-scoring policy."""
    __tablename__ = "policy_versions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    policy_type: Mapped[str] = mapped_column(String(64))  # e.g. correlation | scoring
    version: Mapped[str] = mapped_column(String(32))
    # JSON-serialised parameters
    correlation_config: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    scoring_config: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    content_hash: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())

    incidents: Mapped[list["Incident"]] = relationship(back_populates="policy_version")


class Detection(Base):
    """Normalised output from a single detector for one run."""
    __tablename__ = "detections"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    run_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("analysis_runs.id"), nullable=False
    )
    evidence_id: Mapped[Optional[str]] = mapped_column(
        String(64), ForeignKey("evidence.id"), nullable=True
    )
    detector_type: Mapped[DetectorType] = mapped_column(Enum(DetectorType))
    detector_name: Mapped[str] = mapped_column(String(128))
    event_time: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    src_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    dst_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    src_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    protocol: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    rule_version_id: Mapped[Optional[str]] = mapped_column(
        String(64), ForeignKey("rule_versions.id"), nullable=True
    )
    model_version_id: Mapped[Optional[str]] = mapped_column(
        String(64), ForeignKey("model_versions.id"), nullable=True
    )
    severity: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    # JSON snapshot of features used for anomaly detections
    feature_snapshot: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # bounded raw excerpt from detector output
    raw_output_excerpt: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    normalizer_version: Mapped[str] = mapped_column(String(32), default="1.0")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())

    run: Mapped["AnalysisRun"] = relationship(back_populates="detections")
    evidence: Mapped[Optional["Evidence"]] = relationship(back_populates="detections")
    rule_version: Mapped[Optional["RuleVersion"]] = relationship(
        back_populates="detections"
    )
    model_version: Mapped[Optional["ModelVersion"]] = relationship(
        back_populates="detections"
    )
    incident_links: Mapped[list["IncidentDetection"]] = relationship(
        back_populates="detection"
    )


class Incident(Base):
    """A correlated group of detections with a deterministic risk score."""
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    run_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("analysis_runs.id"), nullable=False
    )
    policy_version_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("policy_versions.id"), nullable=False
    )
    status: Mapped[IncidentStatus] = mapped_column(
        Enum(IncidentStatus), default=IncidentStatus.open
    )
    severity: Mapped[SeverityBand] = mapped_column(Enum(SeverityBand))
    risk_score: Mapped[float] = mapped_column(Float)
    # JSON-serialised scoring factor breakdown
    score_factors: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    correlation_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    first_seen: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    last_seen: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), onupdate=func.now()
    )

    run: Mapped["AnalysisRun"] = relationship(back_populates="incidents")
    policy_version: Mapped["PolicyVersion"] = relationship(back_populates="incidents")
    detection_links: Mapped[list["IncidentDetection"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan"
    )
    explanations: Mapped[list["Explanation"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan"
    )
    response_audits: Mapped[list["ResponseAudit"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan"
    )


class IncidentDetection(Base):
    """Join table preserving why a detection was grouped into an incident."""
    __tablename__ = "incident_detections"

    incident_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("incidents.id"), primary_key=True
    )
    detection_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("detections.id"), primary_key=True
    )
    correlation_reason: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)

    incident: Mapped["Incident"] = relationship(back_populates="detection_links")
    detection: Mapped["Detection"] = relationship(back_populates="incident_links")


class Explanation(Base):
    """Immutable record of one LLM explanation generation attempt."""
    __tablename__ = "explanations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    incident_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("incidents.id"), nullable=False
    )
    model_id: Mapped[str] = mapped_column(String(128))
    prompt_version: Mapped[str] = mapped_column(String(32))
    # Raw JSON from LLM
    raw_output: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # Validated/sanitised JSON (after validation passes)
    validated_output: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    validation_status: Mapped[ValidationStatus] = mapped_column(
        Enum(ValidationStatus), default=ValidationStatus.pending
    )
    # JSON list of validator findings
    validation_findings: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    llm_latency_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())

    incident: Mapped["Incident"] = relationship(back_populates="explanations")
    citations: Mapped[list["ExplanationCitation"]] = relationship(
        back_populates="explanation", cascade="all, delete-orphan"
    )


class ExplanationCitation(Base):
    """A single evidence/detection/rule reference in an explanation."""
    __tablename__ = "explanation_citations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    explanation_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("explanations.id"), nullable=False
    )
    evidence_id: Mapped[Optional[str]] = mapped_column(
        String(64), ForeignKey("evidence.id"), nullable=True
    )
    record_type: Mapped[str] = mapped_column(String(32))  # evidence | detection | rule
    record_id: Mapped[str] = mapped_column(String(64))
    # Which claim in the explanation this supports
    claim_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    explanation: Mapped["Explanation"] = relationship(back_populates="citations")
    evidence: Mapped[Optional["Evidence"]] = relationship(back_populates="citations")


class ResponseAudit(Base):
    """Immutable record of a simulated (never real) response action."""
    __tablename__ = "response_audit"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    incident_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("incidents.id"), nullable=False
    )
    proposed_action: Mapped[str] = mapped_column(String(256))
    action_target: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    action_scope: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    policy_decision: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    simulation_status: Mapped[SimulationStatus] = mapped_column(
        Enum(SimulationStatus), default=SimulationStatus.proposed
    )
    # Always True — enforced at application level
    simulated_only: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    actor: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    result_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())

    incident: Mapped["Incident"] = relationship(back_populates="response_audits")


class EventLog(Base):
    """Optional structured event/transition log for observability."""
    __tablename__ = "event_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    incident_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    component: Mapped[str] = mapped_column(String(128))
    event_type: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32))
    message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    duration_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())
