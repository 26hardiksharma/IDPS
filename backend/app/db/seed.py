"""
Database seeder and bootstrap script for XAI-IDPS.
Populates:
  - Snort rules and rule versions from rule-manifest.json
  - Default Anomaly Model version
  - Default Correlation and Risk-Scoring Policy version
  - An initial demo AnalysisRun, Incident, and Explanation if requested
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

from app.core.config import get_settings
from app.core.logging import configure_logging, get_logger
from app.correlation.risk_scoring import get_scoring_config, SCORING_POLICY_VERSION
from app.db.models import RuleStatus
from app.db.session import async_session_factory, create_all_tables
from app.detection.anomaly_detector import (
    MODEL_NAME as ANOMALY_MODEL_NAME,
    MODEL_VERSION as ANOMALY_MODEL_VERSION,
    FEATURE_SCHEMA_VERSION,
    threshold_config_dict,
)
from app.provenance.version_registry import VersionRegistry

logger = get_logger(__name__)


async def seed_database(create_demo_run: bool = False) -> None:
    settings = get_settings()
    configure_logging(settings.LOG_LEVEL)
    logger.info("seeding_database_start")

    # 1. Ensure tables exist
    await create_all_tables()

    async with async_session_factory() as session:
        registry = VersionRegistry(session)

        # 2. Register default Anomaly Model Version
        threshold_cfg = threshold_config_dict(settings)
        model_ver = await registry.get_or_create_model_version(
            detector_type="threshold",
            model_name=ANOMALY_MODEL_NAME,
            version=ANOMALY_MODEL_VERSION,
            feature_schema_version=FEATURE_SCHEMA_VERSION,
            threshold_config=threshold_cfg,
        )
        logger.info("model_version_registered", version_id=model_ver.id)

        # 3. Register default Policy Version
        policy_ver = await registry.get_or_create_policy_version(
            policy_type="correlation_and_scoring",
            version=SCORING_POLICY_VERSION,
            correlation_config={"time_window_seconds": settings.CORRELATION_TIME_WINDOW_SECONDS},
            scoring_config=get_scoring_config(),
        )
        logger.info("policy_version_registered", version_id=policy_ver.id)

        # 4. Register Snort Rules from manifest
        manifest_path = Path("rules/snort/rule-manifest.json")
        if manifest_path.exists():
            try:
                manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
                rules_list = manifest_data.get("rules", [])
                for r in rules_list:
                    rule_id = r.get("rule_id")
                    version = str(r.get("rev", 1))
                    status_str = r.get("status", "active")
                    status_enum = RuleStatus.active if status_str == "active" else RuleStatus.candidate
                    content = f"sid:{r.get('sid')}; rev:{r.get('rev')}; msg:'{r.get('description')}';"
                    
                    rule_obj, ver_obj = await registry.register_rule_version(
                        rule_id=rule_id,
                        version=version,
                        content=content,
                        status=status_enum,
                    )
                    logger.info("rule_registered", rule_id=rule_id, rev=version)
            except Exception as e:
                logger.error("rule_manifest_seed_failed", error=str(e))

        await session.commit()

    logger.info("seeding_database_complete")


if __name__ == "__main__":
    asyncio.run(seed_database())
