"""
XAI-IDPS FastAPI application entry point.

Binds to localhost by default (NFR-001).
All business logic is in services, not route handlers.
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from http import HTTPStatus
from typing import AsyncIterator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api import explanations, incidents, metrics, response_simulations, runs, rules
from app.core.config import get_settings
from app.core.errors import XAIIDPSError
from app.core.logging import configure_logging, get_logger
from app.db.session import create_all_tables

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    configure_logging(settings.LOG_LEVEL)
    logger.info("xai_idps_starting", env=settings.APP_ENV)
    await create_all_tables()
    logger.info("database_ready")
    yield
    logger.info("xai_idps_shutdown")


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title="XAI-IDPS API",
        description=(
            "Explainable Hybrid Intrusion Detection and Prevention System. "
            "Local-first, simulation-only response, deterministic risk scoring."
        ),
        version="1.0.0",
        lifespan=lifespan,
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
    )

    # CORS — localhost only in development
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Domain error handler ──────────────────────────────────────────────────
    @app.exception_handler(XAIIDPSError)
    async def domain_error_handler(request: Request, exc: XAIIDPSError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.http_status,
            content={
                "error_code": exc.error_code,
                "message": exc.message,
                "detail": exc.detail,
            },
        )

    # ── Routers ───────────────────────────────────────────────────────────────
    app.include_router(runs.router)
    app.include_router(incidents.router)
    app.include_router(explanations.router)
    app.include_router(rules.router)
    app.include_router(metrics.router)
    app.include_router(response_simulations.router)

    @app.get("/health", tags=["health"])
    async def health_check() -> dict:
        return {"status": "ok", "service": "xai-idps"}

    return app


app = create_app()
