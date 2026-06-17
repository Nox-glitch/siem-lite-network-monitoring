
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
from database.models import Event, Severity
from api.schemas import EventOut, EventListResponse

logger   = logging.getLogger(__name__)
router   = APIRouter()
REDIS_URL = __import__("os").getenv("REDIS_URL", "redis://localhost:6379")



@router.get("", response_model=EventListResponse)
async def list_events(
    page:        int            = Query(1, ge=1),
    size:        int            = Query(50, ge=1, le=500),
    severity:    Optional[Severity] = None,
    category:    Optional[str]  = None,
    event_type:  Optional[str]  = None,
    source_ip:   Optional[str]  = None,
    username:    Optional[str]  = None,
    search:      Optional[str]  = None,
    since:       Optional[int]  = Query(None, description="Last N minutes"),
    db:          AsyncSession   = Depends(get_db),
):

    filters = []

    if severity:
        filters.append(Event.severity == severity)
    if category:
        filters.append(Event.category == category)
    if event_type:
        filters.append(Event.event_type == event_type)
    if source_ip:
        filters.append(Event.source_ip == source_ip)
    if username:
        filters.append(Event.username.ilike(f"%{username}%"))
    if since:
        cutoff = datetime.utcnow() - timedelta(minutes=since)
        filters.append(Event.timestamp >= cutoff)
    if search:
        filters.append(
            or_(
                Event.message.ilike(f"%{search}%"),
                Event.source_ip.ilike(f"%{search}%"),
                Event.username.ilike(f"%{search}%"),
                Event.event_type.ilike(f"%{search}%"),
            )
        )

    where = and_(*filters) if filters else True


    count_q  = await db.execute(select(func.count()).select_from(Event).where(where))
    total    = count_q.scalar_one()


    offset   = (page - 1) * size
    result   = await db.execute(
        select(Event).where(where).order_by(desc(Event.timestamp)).offset(offset).limit(size)
    )
    items    = result.scalars().all()

    return EventListResponse(total=total, page=page, size=size, items=items)



@router.get("/{event_id}", response_model=EventOut)
async def get_event(event_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Event).where(Event.id == event_id))
    event  = result.scalar_one_or_none()
    if not event:
        raise HTTPException(status_code=404, detail=f"Event {event_id} not found")
    return event



async def _event_generator() -> AsyncGenerator[str, None]:
    """Subscribe to Redis and yield new events as SSE data frames."""
    r      = aioredis.from_url(REDIS_URL)
    pubsub = r.pubsub()
    await pubsub.subscribe("siem:events")

    try:
        async for message in pubsub.listen():
            if message["type"] != "message":
                continue
            try:
                data = json.loads(message["data"])
                yield f"data: {json.dumps(data)}\n\n"
            except (json.JSONDecodeError, Exception) as e:
                logger.warning(f"SSE parse error: {e}")
    except asyncio.CancelledError:
        pass
    finally:
        await pubsub.unsubscribe("siem:events")
        await r.aclose()


@router.get("/stream/live")
async def stream_events():

    return StreamingResponse(
        _event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control":    "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
