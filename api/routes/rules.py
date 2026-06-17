
import os
import logging
from datetime import datetime

import yaml
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from database.connection import get_db
from database.models import DetectionRule, Severity
from api.schemas import RuleOut, RuleUpdateRequest

logger     = logging.getLogger(__name__)
router     = APIRouter()
RULES_PATH = os.path.join(os.path.dirname(__file__), "../../detection/rules.yaml")



@router.get("", response_model=list[RuleOut])
async def list_rules(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(DetectionRule).order_by(DetectionRule.rule_id))
    return result.scalars().all()



@router.get("/{rule_id_or_pk}", response_model=RuleOut)
async def get_rule(rule_id_or_pk: str, db: AsyncSession = Depends(get_db)):
    # Try by PK (int) first, then by rule_id string
    query = None
    if rule_id_or_pk.isdigit():
        query = await db.execute(
            select(DetectionRule).where(DetectionRule.id == int(rule_id_or_pk))
        )
    else:
        query = await db.execute(
            select(DetectionRule).where(DetectionRule.rule_id == rule_id_or_pk)
        )
    rule = query.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail=f"Rule '{rule_id_or_pk}' not found")
    return rule



@router.patch("/{rule_id_or_pk}", response_model=RuleOut)
async def update_rule(
    rule_id_or_pk: str,
    body:          RuleUpdateRequest,
    db:            AsyncSession = Depends(get_db),
):
    query = None
    if rule_id_or_pk.isdigit():
        query = await db.execute(
            select(DetectionRule).where(DetectionRule.id == int(rule_id_or_pk))
        )
    else:
        query = await db.execute(
            select(DetectionRule).where(DetectionRule.rule_id == rule_id_or_pk)
        )
    rule = query.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail=f"Rule '{rule_id_or_pk}' not found")

    if body.enabled is not None:
        rule.enabled = body.enabled
    if body.severity is not None:
        rule.severity = body.severity
    if body.description is not None:
        rule.description = body.description

    await db.commit()
    await db.refresh(rule)
    logger.info(f"Rule {rule.rule_id} updated: {body.model_dump(exclude_none=True)}")
    return rule



@router.post("/sync", summary="Reload rules.yaml into the database")
async def sync_rules(db: AsyncSession = Depends(get_db)):
    try:
        with open(RULES_PATH) as f:
            data = yaml.safe_load(f)
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail=f"rules.yaml not found at {RULES_PATH}")

    raw_rules  = data.get("rules", [])
    upserted   = 0
    skipped    = 0

    for raw in raw_rules:
        existing_q = await db.execute(
            select(DetectionRule).where(DetectionRule.rule_id == raw["id"])
        )
        existing = existing_q.scalar_one_or_none()

        if existing:
            # Preserve user overrides (enabled flag, fire_count)
            existing.name             = raw["name"]
            existing.description      = raw.get("description", "")
            existing.severity         = Severity(raw["severity"])
            existing.category         = raw.get("category", "unknown")
            existing.condition_type   = raw["condition_type"]
            existing.condition_config = raw.get("condition", {})
            existing.playbook         = raw.get("playbook")
            existing.mitre_tactic     = raw.get("mitre_tactic")
            existing.mitre_technique  = raw.get("mitre_technique")
            skipped += 1
        else:
            rule = DetectionRule(
                rule_id          = raw["id"],
                name             = raw["name"],
                description      = raw.get("description", ""),
                enabled          = raw.get("enabled", True),
                severity         = Severity(raw["severity"]),
                category         = raw.get("category", "unknown"),
                condition_type   = raw["condition_type"],
                condition_config = raw.get("condition", {}),
                playbook         = raw.get("playbook"),
                mitre_tactic     = raw.get("mitre_tactic"),
                mitre_technique  = raw.get("mitre_technique"),
            )
            db.add(rule)
            upserted += 1

    await db.commit()
    logger.info(f"Rules sync: {upserted} inserted, {skipped} updated")
    return {"status": "ok", "inserted": upserted, "updated": skipped, "total": len(raw_rules)}
