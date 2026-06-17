
import json
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Optional, AsyncGenerator

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, Query, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, desc, or_

from database.connection import get_db
from database.models import Alert, Severity, AlertStatus
from api.schemas import AlertOut, AlertListResponse, AlertUpdateRequest

logger    = logging.getLogger(__name__)
router    = APIRouter()
REDIS_URL = __import__("os").getenv("REDIS_URL", "redis://localhost:6379")



@router.get("", response_model=AlertListResponse)
async def list_alerts(
    page:       int                  = Query(1, ge=1),
    size:       int                  = Query(50, ge=1, le=200),
    severity:   Optional[Severity]   = None,
    status:     Optional[AlertStatus]= None,
    rule_id:    Optional[str]        = None,
    source_ip:  Optional[str]        = None,
    search:     Optional[str]        = None,
    since:      Optional[int]        = Query(None, description="Last N minutes"),
    db:         AsyncSession         = Depends(get_db),
):
    filters = []

    if severity:
        filters.append(Alert.severity == severity)
    if status:
        filters.append(Alert.status == status)
    if rule_id:
        filters.append(Alert.rule_id == rule_id)
    if source_ip:
        filters.append(Alert.source_ip == source_ip)
    if since:
        cutoff = datetime.utcnow() - timedelta(minutes=since)
        filters.append(Alert.created_at >= cutoff)
    if search:
        filters.append(
            or_(
                Alert.title.ilike(f"%{search}%"),
                Alert.rule_name.ilike(f"%{search}%"),
                Alert.source_ip.ilike(f"%{search}%"),
                Alert.description.ilike(f"%{search}%"),
            )
        )

    where  = and_(*filters) if filters else True
    count_q = await db.execute(select(func.count()).select_from(Alert).where(where))
    total  = count_q.scalar_one()

    offset = (page - 1) * size
    result = await db.execute(
        select(Alert).where(where).order_by(desc(Alert.created_at)).offset(offset).limit(size)
    )
    items  = result.scalars().all()

    return AlertListResponse(total=total, page=page, size=size, items=items)



@router.get("/{alert_id}", response_model=AlertOut)
async def get_alert(alert_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert  = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
    return alert



@router.patch("/{alert_id}", response_model=AlertOut)
async def update_alert(
    alert_id: int,
    body:     AlertUpdateRequest,
    db:       AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert  = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")

    if body.status is not None:
        alert.status     = body.status
        alert.updated_at = datetime.utcnow()
    if body.analyst_notes is not None:
        alert.analyst_notes = body.analyst_notes
        alert.updated_at    = datetime.utcnow()

    await db.commit()
    await db.refresh(alert)
    return alert



@router.post("/{alert_id}/acknowledge", response_model=AlertOut)
async def acknowledge_alert(alert_id: int, db: AsyncSession = Depends(get_db)):
    return await _set_status(alert_id, AlertStatus.ACKNOWLEDGED, db)


@router.post("/{alert_id}/resolve", response_model=AlertOut)
async def resolve_alert(alert_id: int, db: AsyncSession = Depends(get_db)):
    return await _set_status(alert_id, AlertStatus.RESOLVED, db)


@router.post("/{alert_id}/false-positive", response_model=AlertOut)
async def mark_false_positive(alert_id: int, db: AsyncSession = Depends(get_db)):
    return await _set_status(alert_id, AlertStatus.FALSE_POSITIVE, db)


async def _set_status(alert_id: int, status: AlertStatus, db: AsyncSession) -> Alert:
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert  = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
    alert.status     = status
    alert.updated_at = datetime.utcnow()
    await db.commit()
    await db.refresh(alert)
    return alert



async def _alert_generator() -> AsyncGenerator[str, None]:
    r      = aioredis.from_url(REDIS_URL)
    pubsub = r.pubsub()
    await pubsub.subscribe("siem:alerts")
    try:
        async for message in pubsub.listen():
            if message["type"] != "message":
                continue
            try:
                yield f"data: {message['data'].decode()}\n\n"
            except Exception:
                pass
    except asyncio.CancelledError:
        pass
    finally:
        await pubsub.unsubscribe("siem:alerts")
        await r.aclose()


@router.get("/stream/live")
async def stream_alerts():

    return StreamingResponse(
        _alert_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
