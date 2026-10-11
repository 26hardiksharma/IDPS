"""
Structured explanation schema — Pydantic models for LLM output validation.
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class ValidationStatus(str, Enum):
    pending = "pending"
    valid = "valid"
    partially_valid = "partially_valid"
    invalid = "invalid"
    failed = "failed"


class ObservationItem(BaseModel):
    claim: str
    evidence_ids: list[str] = Field(default_factory=list)
    validation_type: Optional[str] = None


class InterpretationItem(BaseModel):
    claim: str
    evidence_ids: list[str] = Field(default_factory=list)
    confidence: Optional[str] = None


class ExplanationOutput(BaseModel):
    """
    Expected structure of the JSON returned by the local LLM.
    All fields except incident_id are advisory/informational.
    """
    incident_id: str
    summary: str
    observations: list[ObservationItem] = Field(default_factory=list)
    interpretations: list[InterpretationItem] = Field(default_factory=list)
    evidence_references: list[str] = Field(default_factory=list)
    uncertainties: list[str] = Field(default_factory=list)
    recommended_next_steps: list[str] = Field(default_factory=list)
    model_id: Optional[str] = None
    prompt_version: Optional[str] = None
    validation_status: Optional[str] = None

    class Config:
        extra = "allow"  # tolerate extra fields from LLM without crashing
