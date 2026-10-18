"""
XAI-IDPS Application Configuration
Reads settings from environment variables / .env file.
"""
from __future__ import annotations

import os
from pathlib import Path
from functools import lru_cache
from typing import Literal

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=("../.env", ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Application ─────────────────────────────────────────────────────────
    APP_ENV: Literal["development", "testing", "production"] = "development"
    API_HOST: str = "127.0.0.1"
    API_PORT: int = 8000
    LOG_LEVEL: str = "INFO"

    # ── Database ─────────────────────────────────────────────────────────────
    DATABASE_URL: str = "sqlite+aiosqlite:///./data/xai_idps.db"

    # ── PCAP / data directories ──────────────────────────────────────────────
    PCAP_ROOT: Path = Path("./data/pcaps")
    DATA_DIR: Path = Path("./data")
    MAX_PCAP_MB: int = 100

    # ── Snort ────────────────────────────────────────────────────────────────
    SNORT_BIN: str = "snort"
    SNORT_CONFIG: Path = Path("./config/snort/snort.lua")
    SNORT_RULES_DIR: Path = Path("./rules/snort")
    SNORT_OUTPUT_DIR: Path = Path("./data/outputs/snort")
    SNORT_TIMEOUT_SECONDS: int = 300

    # ── Ollama / Local LLM ───────────────────────────────────────────────────
    OLLAMA_BASE_URL: str = "http://127.0.0.1:11434"
    OLLAMA_MODEL: str = "llama3.2"
    EXPLANATION_TIMEOUT_SECONDS: int = 60
    PROMPT_TEMPLATE_VERSION: str = "1.0"

    # ── Anomaly detection ────────────────────────────────────────────────────
    ANOMALY_THRESHOLD_DISTINCT_PORTS: int = 20
    ANOMALY_THRESHOLD_PKT_RATE: float = 100.0
    ANOMALY_THRESHOLD_DNS_QUERIES: int = 30
    ANOMALY_THRESHOLD_DNS_ENTROPY: float = 3.5
    ANOMALY_FEATURE_WINDOW_SECONDS: int = 30

    # ── Correlation / scoring ────────────────────────────────────────────────
    CORRELATION_TIME_WINDOW_SECONDS: int = 300
    SCORING_POLICY_VERSION: str = "1.0"

    # ── Evaluation ───────────────────────────────────────────────────────────
    EVAL_CORPUS_DIR: Path = Path("./data/corpus")

    @field_validator("PCAP_ROOT", "DATA_DIR", "SNORT_OUTPUT_DIR",
                     "EVAL_CORPUS_DIR", mode="before")
    @classmethod
    def _coerce_path(cls, v: object) -> Path:
        return Path(str(v))

    @model_validator(mode="after")
    def _ensure_dirs(self) -> "Settings":
        """Create required directories if they do not exist yet."""
        for d in (
            self.PCAP_ROOT,
            self.DATA_DIR,
            self.SNORT_OUTPUT_DIR,
            self.EVAL_CORPUS_DIR,
        ):
            d.mkdir(parents=True, exist_ok=True)
        return self

    @property
    def max_pcap_bytes(self) -> int:
        return self.MAX_PCAP_MB * 1024 * 1024


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
