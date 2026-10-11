"""
Version registry — manages rule_versions, model_versions, and policy_versions.
Provides helpers to look up or create the canonical version record for a
given identifier + version string.
"""
from __future__ import annotations

import json
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import NotFoundError
from app.db.models import ModelVersion, PolicyVersion, RuleStatus, RuleVersion
from app.provenance.hashing import hash_text
from app.provenance.id_factory import new_id


class VersionRegistry:
    def __init__(self, session: AsyncSession) -> None:
        self._db = session

    # ── Rule versions ─────────────────────────────────────────────────────────

    async def get_rule_version(self, rule_version_id: str) -> RuleVersion:
        row = await self._db.get(RuleVersion, rule_version_id)
        if row is None:
            raise NotFoundError(f"Rule version {rule_version_id} not found")
        return row

    async def list_rule_versions(
        self,
        include_candidates: bool = True,
    ) -> list[RuleVersion]:
        stmt = select(RuleVersion).order_by(RuleVersion.created_at.desc())
        if not include_candidates:
            stmt = stmt.where(RuleVersion.status == RuleStatus.active)
        result = await self._db.execute(stmt)
        return list(result.scalars().all())

    async def register_rule_version(
        self,
        rule_id: str,
        version: str,
        content: str,
        source: str = "local",
        test_result_ref: str | None = None,
        status: RuleStatus = RuleStatus.candidate,
    ) -> RuleVersion:
        sha256 = hash_text(content)
        # Check for exact duplicate (same hash already registered)
        stmt = select(RuleVersion).where(RuleVersion.sha256 == sha256)
        existing = (await self._db.execute(stmt)).scalar_one_or_none()
        if existing:
            return existing
        rv = RuleVersion(
            id=new_id("rulever"),
            rule_id=rule_id,
            version=version,
            content=content,
            sha256=sha256,
            source=source,
            status=status,
            test_result_ref=test_result_ref,
        )
        self._db.add(rv)
        await self._db.flush()
        return rv

    # ── Model versions ────────────────────────────────────────────────────────

    async def get_model_version(self, model_version_id: str) -> ModelVersion:
        row = await self._db.get(ModelVersion, model_version_id)
        if row is None:
            raise NotFoundError(f"Model version {model_version_id} not found")
        return row

    async def get_or_create_model_version(
        self,
        detector_type: str,
        model_name: str,
        version: str,
        feature_schema_version: str,
        threshold_config: dict | None = None,
        artifact_hash: str | None = None,
    ) -> ModelVersion:
        stmt = select(ModelVersion).where(
            ModelVersion.model_name == model_name,
            ModelVersion.version == version,
        )
        existing = (await self._db.execute(stmt)).scalar_one_or_none()
        if existing:
            return existing
        mv = ModelVersion(
            id=new_id("modver"),
            detector_type=detector_type,
            model_name=model_name,
            version=version,
            feature_schema_version=feature_schema_version,
            artifact_hash=artifact_hash,
            threshold_config=json.dumps(threshold_config) if threshold_config else None,
        )
        self._db.add(mv)
        await self._db.flush()
        return mv

    # ── Policy versions ───────────────────────────────────────────────────────

    async def get_policy_version(self, policy_version_id: str) -> PolicyVersion:
        row = await self._db.get(PolicyVersion, policy_version_id)
        if row is None:
            raise NotFoundError(f"Policy version {policy_version_id} not found")
        return row

    async def get_or_create_policy_version(
        self,
        policy_type: str,
        version: str,
        correlation_config: dict | None = None,
        scoring_config: dict | None = None,
    ) -> PolicyVersion:
        content = json.dumps(
            {
                "policy_type": policy_type,
                "version": version,
                "correlation_config": correlation_config,
                "scoring_config": scoring_config,
            },
            sort_keys=True,
        )
        content_hash = hash_text(content)
        stmt = select(PolicyVersion).where(
            PolicyVersion.content_hash == content_hash
        )
        existing = (await self._db.execute(stmt)).scalar_one_or_none()
        if existing:
            return existing
        pv = PolicyVersion(
            id=new_id("polver"),
            policy_type=policy_type,
            version=version,
            correlation_config=json.dumps(correlation_config) if correlation_config else None,
            scoring_config=json.dumps(scoring_config) if scoring_config else None,
            content_hash=content_hash,
        )
        self._db.add(pv)
        await self._db.flush()
        return pv
