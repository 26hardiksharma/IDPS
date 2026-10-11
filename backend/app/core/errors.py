"""
Application-wide exception types.
All domain errors inherit from XAIIDPSError so API handlers can catch
them uniformly and return consistent JSON error responses.
"""
from __future__ import annotations

from http import HTTPStatus


class XAIIDPSError(Exception):
    """Base class for all XAI-IDPS domain errors."""

    http_status: int = HTTPStatus.INTERNAL_SERVER_ERROR
    error_code: str = "internal_error"

    def __init__(self, message: str, detail: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.detail = detail


# ── Input / validation ────────────────────────────────────────────────────────

class ValidationError(XAIIDPSError):
    http_status = HTTPStatus.UNPROCESSABLE_ENTITY
    error_code = "validation_error"


class InputRejectedError(XAIIDPSError):
    """Raised when a PCAP or other input fails safety/sanity checks."""
    http_status = HTTPStatus.BAD_REQUEST
    error_code = "input_rejected"


class NotFoundError(XAIIDPSError):
    http_status = HTTPStatus.NOT_FOUND
    error_code = "not_found"


class ConflictError(XAIIDPSError):
    """Raised on duplicate run execution or conflicting state."""
    http_status = HTTPStatus.CONFLICT
    error_code = "conflict"


# ── Pipeline / detector ───────────────────────────────────────────────────────

class DetectorError(XAIIDPSError):
    """A detection stage failed; partial results may still be available."""
    http_status = HTTPStatus.INTERNAL_SERVER_ERROR
    error_code = "detector_error"


class SnortError(DetectorError):
    error_code = "snort_error"


class AnomalyError(DetectorError):
    error_code = "anomaly_error"


class FeatureExtractionError(DetectorError):
    error_code = "feature_extraction_error"


# ── Explanation ───────────────────────────────────────────────────────────────

class OllamaUnavailableError(XAIIDPSError):
    http_status = HTTPStatus.SERVICE_UNAVAILABLE
    error_code = "ollama_unavailable"


class ExplanationValidationError(XAIIDPSError):
    http_status = HTTPStatus.UNPROCESSABLE_ENTITY
    error_code = "explanation_validation_error"


# ── Database ──────────────────────────────────────────────────────────────────

class DatabaseError(XAIIDPSError):
    error_code = "database_error"


# ── Response simulation ───────────────────────────────────────────────────────

class SimulationError(XAIIDPSError):
    error_code = "simulation_error"
