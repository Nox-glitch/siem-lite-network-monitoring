"""
SIEM Lite - Network Devices Router (fixed: eager loading via selectinload)
"""

import json
import asyncio
import logging
import os
from datetime import datetime, timedelta
from typing import Optional, AsyncGenerator

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc, and_
from sqlalchemy.orm import selectinload

from database.connection import get_db
from database.models import (
    NetworkDevice, DeviceMetric, DeviceThreshold,
    DeviceNotification, DeviceStatus, DeviceType
)

logger    = logging.getLogger(__name__)
router    = APIRouter()
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class DeviceCreate(BaseModel):
    name:         str
    ip_address:   str
    device_type:  DeviceType  = DeviceType.OTHER
    vendor:       Optional[str] = None
    model:        Optional[str] = None
    location:     Optional[str] = None
    notes:        Optional[str] = None
    is_monitored: bool = True


class DeviceUpdate(BaseModel):
    name:         Optional[str]  = None
    location:     Optional[str]  = None
    vendor:       Optional[str]  = None
    model:        Optional[str]  = None
    notes:        Optional[str]  = None
    is_monitored: Optional[bool] = None


class ThresholdUpdate(BaseModel):
    temp_warn:          Optional[float] = None
    temp_critical:      Optional[float] = None
    cpu_warn:           Optional[float] = None
    cpu_critical:       Optional[float] = None
    mem_warn:           Optional[float] = None
    mem_critical:       Optional[float] = None
    bandwidth_warn:     Optional[float] = None
    bandwidth_critical: Optional[float] = None
    latency_warn:       Optional[float] = None
    latency_critical:   Optional[float] = None
    duration_seconds:   Optional[int]   = None
    notify_slack:       Optional[bool]  = None
    notify_email:       Optional[bool]  = None


# ── Helper: query with eager-loaded relationships ─────────────────────────────

def _with_relations():
    """Always load thresholds eagerly to avoid MissingGreenlet in async."""
    return selectinload(NetworkDevice.thresholds)


# ── Helper: serialize device (safe — no lazy loads) ───────────────────────────

def _device_dict(d: NetworkDevice, latest: DeviceMetric = None, thresh=None) -> dict:
    uptime_h = round((d.uptime_seconds or 0) / 3600, 1)
    result = {
        "id":           d.id,
        "name":         d.name,
        "ip_address":   d.ip_address,
        "mac_address":  d.mac_address,
        "device_type":  d.device_type.value,
        "vendor":       d.vendor,
        "model":        d.model,
        "location":     d.location,
        "status":       d.status.value,
        "is_monitored": d.is_monitored,
        "uptime_hours": uptime_h,
        "last_seen":    d.last_seen.isoformat() if d.last_seen else None,
        "added_at":     d.added_at.isoformat()  if d.added_at  else None,
        "notes":        d.notes,
    }

    if latest:
        result["latest_metrics"] = {
            "temperature_c":      latest.temperature_c,
            "cpu_percent":        latest.cpu_percent,
            "memory_percent":     latest.memory_percent,
            "bandwidth_in_mbps":  latest.bandwidth_in_mbps,
            "bandwidth_out_mbps": latest.bandwidth_out_mbps,
            "latency_ms":         latest.latency_ms,
            "error_count":        latest.error_count,
            "timestamp":          latest.timestamp.isoformat() if latest.timestamp else None,
        }

    # Use the explicitly passed thresh (already loaded) — never touch d.thresholds
    t = thresh
    if t:
        result["thresholds"] = {
            "temp_warn":        t.temp_warn,        "temp_critical":      t.temp_critical,
            "cpu_warn":         t.cpu_warn,          "cpu_critical":       t.cpu_critical,
            "mem_warn":         t.mem_warn,          "mem_critical":       t.mem_critical,
            "bandwidth_warn":   t.bandwidth_warn,    "bandwidth_critical": t.bandwidth_critical,
            "latency_warn":     t.latency_warn,      "latency_critical":   t.latency_critical,
            "duration_seconds": t.duration_seconds,
            "notify_slack":     t.notify_slack,      "notify_email":       t.notify_email,
        }
    return result


# ── Fleet summary ─────────────────────────────────────────────────────────────

@router.get("/summary")
async def network_summary(db: AsyncSession = Depends(get_db)):
    total_r = await db.execute(select(func.count()).select_from(NetworkDevice))
    total   = total_r.scalar_one()

    status_r  = await db.execute(
        select(NetworkDevice.status, func.count()).group_by(NetworkDevice.status)
    )
    by_status = {r[0].value: r[1] for r in status_r.all()}

    type_r  = await db.execute(
        select(NetworkDevice.device_type, func.count()).group_by(NetworkDevice.device_type)
    )
    by_type = {r[0].value: r[1] for r in type_r.all()}

    unack_r = await db.execute(
        select(func.count()).select_from(DeviceNotification)
        .where(DeviceNotification.acknowledged == False)
    )
    unacked = unack_r.scalar_one()

    crit_r  = await db.execute(
        select(func.count()).select_from(DeviceNotification)
        .where(and_(DeviceNotification.acknowledged == False,
                    DeviceNotification.level == "critical"))
    )
    critical_notifs = crit_r.scalar_one()

    return {
        "total_devices":          total,
        "by_status":              by_status,
        "by_type":                by_type,
        "unacked_notifications":  unacked,
        "critical_notifications": critical_notifs,
        "online":  by_status.get("online",   0),
        "offline": by_status.get("offline",  0),
        "warning": by_status.get("warning",  0) + by_status.get("critical", 0),
    }


# ── Device CRUD ───────────────────────────────────────────────────────────────

@router.get("/devices")
async def list_devices(
    device_type: Optional[DeviceType]   = None,
    status:      Optional[DeviceStatus] = None,
    db:          AsyncSession           = Depends(get_db),
):
    q = select(NetworkDevice).options(_with_relations())
    if device_type:
        q = q.where(NetworkDevice.device_type == device_type)
    if status:
        q = q.where(NetworkDevice.status == status)
    q = q.order_by(NetworkDevice.device_type, NetworkDevice.name)

    result  = await db.execute(q)
    devices = result.scalars().all()

    out = []
    for d in devices:
        # Latest metric — explicit query, not via relationship
        latest_r = await db.execute(
            select(DeviceMetric)
            .where(DeviceMetric.device_id == d.id)
            .order_by(desc(DeviceMetric.timestamp))
            .limit(1)
        )
        latest = latest_r.scalar_one_or_none()

        # Threshold — already eagerly loaded, access via attribute safely
        thresh_r = await db.execute(
            select(DeviceThreshold).where(DeviceThreshold.device_id == d.id)
        )
        thresh = thresh_r.scalar_one_or_none()

        out.append(_device_dict(d, latest, thresh))
    return out


@router.post("/devices", status_code=201)
async def add_device(body: DeviceCreate, db: AsyncSession = Depends(get_db)):
    existing_r = await db.execute(
        select(NetworkDevice).where(NetworkDevice.ip_address == body.ip_address)
    )
    if existing_r.scalar_one_or_none():
        raise HTTPException(409, f"Device with IP {body.ip_address} already exists")

    device = NetworkDevice(**body.model_dump())
    db.add(device)
    await db.flush()

    thresh = DeviceThreshold(device_id=device.id)
    db.add(thresh)
    await db.commit()
    await db.refresh(device)
    await db.refresh(thresh)
    return _device_dict(device, thresh=thresh)


@router.get("/devices/{device_id}")
async def get_device(device_id: int, db: AsyncSession = Depends(get_db)):
    r = await db.execute(
        select(NetworkDevice)
        .options(_with_relations())
        .where(NetworkDevice.id == device_id)
    )
    d = r.scalar_one_or_none()
    if not d:
        raise HTTPException(404, f"Device {device_id} not found")

    latest_r = await db.execute(
        select(DeviceMetric)
        .where(DeviceMetric.device_id == device_id)
        .order_by(desc(DeviceMetric.timestamp))
        .limit(1)
    )
    thresh_r = await db.execute(
        select(DeviceThreshold).where(DeviceThreshold.device_id == device_id)
    )
    return _device_dict(d, latest_r.scalar_one_or_none(), thresh_r.scalar_one_or_none())


@router.patch("/devices/{device_id}")
async def update_device(device_id: int, body: DeviceUpdate, db: AsyncSession = Depends(get_db)):
    r = await db.execute(
        select(NetworkDevice).options(_with_relations()).where(NetworkDevice.id == device_id)
    )
    d = r.scalar_one_or_none()
    if not d:
        raise HTTPException(404)
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(d, k, v)
    await db.commit()
    await db.refresh(d)
    thresh_r = await db.execute(
        select(DeviceThreshold).where(DeviceThreshold.device_id == device_id)
    )
    return _device_dict(d, thresh=thresh_r.scalar_one_or_none())


@router.delete("/devices/{device_id}", status_code=204)
async def delete_device(device_id: int, db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(NetworkDevice).where(NetworkDevice.id == device_id))
    d = r.scalar_one_or_none()
    if not d:
        raise HTTPException(404)
    await db.delete(d)
    await db.commit()


# ── Metrics time-series ───────────────────────────────────────────────────────

@router.get("/devices/{device_id}/metrics")
async def device_metrics(
    device_id: int,
    hours:     int            = Query(1, ge=1, le=24),
    metric:    Optional[str]  = Query(None),
    db:        AsyncSession   = Depends(get_db),
):
    since  = datetime.utcnow() - timedelta(hours=hours)
    result = await db.execute(
        select(DeviceMetric)
        .where(and_(DeviceMetric.device_id == device_id,
                    DeviceMetric.timestamp >= since))
        .order_by(DeviceMetric.timestamp)
    )
    rows   = result.scalars().all()
    fields = [metric] if metric else [
        "temperature_c", "cpu_percent", "memory_percent",
        "bandwidth_in_mbps", "bandwidth_out_mbps", "latency_ms"
    ]
    return [
        {"timestamp": m.timestamp.isoformat(),
         **{f: getattr(m, f) for f in fields if hasattr(m, f)}}
        for m in rows
    ]


# ── Thresholds ────────────────────────────────────────────────────────────────

@router.get("/devices/{device_id}/thresholds")
async def get_thresholds(device_id: int, db: AsyncSession = Depends(get_db)):
    r = await db.execute(
        select(DeviceThreshold).where(DeviceThreshold.device_id == device_id)
    )
    t = r.scalar_one_or_none()
    if not t:
        raise HTTPException(404, "No thresholds configured for this device")
    return {c.name: getattr(t, c.name)
            for c in DeviceThreshold.__table__.columns if c.name != "id"}


@router.patch("/devices/{device_id}/thresholds")
async def update_thresholds(
    device_id: int, body: ThresholdUpdate, db: AsyncSession = Depends(get_db)
):
    r = await db.execute(
        select(DeviceThreshold).where(DeviceThreshold.device_id == device_id)
    )
    t = r.scalar_one_or_none()
    if not t:
        t = DeviceThreshold(device_id=device_id)
        db.add(t)
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(t, k, v)
    await db.commit()
    return {"status": "updated"}


# ── Notifications ─────────────────────────────────────────────────────────────

@router.get("/notifications")
async def list_notifications(
    unacked_only: bool          = True,
    device_id:    Optional[int] = None,
    level:        Optional[str] = None,
    limit:        int           = Query(100, le=500),
    db:           AsyncSession  = Depends(get_db),
):
    q = select(DeviceNotification).order_by(desc(DeviceNotification.created_at))
    if unacked_only:
        q = q.where(DeviceNotification.acknowledged == False)
    if device_id:
        q = q.where(DeviceNotification.device_id == device_id)
    if level:
        q = q.where(DeviceNotification.level == level)
    q = q.limit(limit)

    result = await db.execute(q)
    rows   = result.scalars().all()
    return [
        {
            "id":           n.id,
            "device_id":    n.device_id,
            "metric":       n.metric,
            "value":        n.value,
            "threshold":    n.threshold,
            "level":        n.level,
            "message":      n.message,
            "acknowledged": n.acknowledged,
            "created_at":   n.created_at.isoformat() if n.created_at else None,
        }
        for n in rows
    ]


@router.post("/notifications/{notif_id}/ack")
async def ack_notification(notif_id: int, db: AsyncSession = Depends(get_db)):
    r = await db.execute(
        select(DeviceNotification).where(DeviceNotification.id == notif_id)
    )
    n = r.scalar_one_or_none()
    if not n:
        raise HTTPException(404)
    n.acknowledged = True
    n.ack_at       = datetime.utcnow()
    await db.commit()
    return {"status": "acknowledged"}


@router.post("/notifications/ack-all")
async def ack_all_notifications(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(DeviceNotification).where(DeviceNotification.acknowledged == False)
    )
    rows = result.scalars().all()
    now  = datetime.utcnow()
    for n in rows:
        n.acknowledged = True
        n.ack_at       = now
    await db.commit()
    return {"acknowledged": len(rows)}


# ── SSE streams ───────────────────────────────────────────────────────────────

SSE_HEADERS = {"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}


async def _stream(channel: str) -> AsyncGenerator[str, None]:
    r      = aioredis.from_url(REDIS_URL)
    pubsub = r.pubsub()
    await pubsub.subscribe(channel)
    try:
        async for msg in pubsub.listen():
            if msg["type"] == "message":
                yield f"data: {msg['data'].decode()}\n\n"
    except asyncio.CancelledError:
        pass
    finally:
        await pubsub.unsubscribe(channel)
        await r.aclose()


@router.get("/stream/metrics")
async def stream_metrics():
    return StreamingResponse(_stream("siem:device_metrics"),
                             media_type="text/event-stream", headers=SSE_HEADERS)


@router.get("/stream/notifications")
async def stream_notifications():
    return StreamingResponse(_stream("siem:device_notifications"),
                             media_type="text/event-stream", headers=SSE_HEADERS)
