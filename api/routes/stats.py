

import logging
from datetime import datetime, timedelta
from collections import defaultdict

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, desc, case

from database.connection import get_db
from database.models import Event, Alert, BlockedIP, Severity, AlertStatus
from api.schemas import (
    DashboardStats, SeverityBreakdown, TimeSeriesPoint,
    TopIP, TopEventType,
)

logger = logging.getLogger(__name__)
router = APIRouter()



@router.get("/dashboard", response_model=DashboardStats)
async def dashboard_stats(
    window_hours: int          = Query(24, ge=1, le=168, description="Lookback window in hours"),
    db:           AsyncSession = Depends(get_db),
):
    since = datetime.utcnow() - timedelta(hours=window_hours)

    total_events_r = await db.execute(
        select(func.count()).select_from(Event).where(Event.timestamp >= since)
    )
    total_events = total_events_r.scalar_one()

    total_alerts_r = await db.execute(
        select(func.count()).select_from(Alert).where(Alert.created_at >= since)
    )
    total_alerts = total_alerts_r.scalar_one()

    open_alerts_r = await db.execute(
        select(func.count()).select_from(Alert).where(Alert.status == AlertStatus.OPEN)
    )
    open_alerts = open_alerts_r.scalar_one()

    critical_r = await db.execute(
        select(func.count()).select_from(Alert).where(
            and_(Alert.severity == Severity.CRITICAL, Alert.status == AlertStatus.OPEN)
        )
    )
    critical_alerts = critical_r.scalar_one()

    blocked_r = await db.execute(
        select(func.count()).select_from(BlockedIP).where(BlockedIP.is_active == True)
    )
    blocked_ips = blocked_r.scalar_one()

    ev_sev_r = await db.execute(
        select(Event.severity, func.count())
        .where(Event.timestamp >= since)
        .group_by(Event.severity)
    )
    ev_sev = dict(ev_sev_r.all())
    events_by_severity = SeverityBreakdown(
        low      = ev_sev.get(Severity.LOW, 0),
        medium   = ev_sev.get(Severity.MEDIUM, 0),
        high     = ev_sev.get(Severity.HIGH, 0),
        critical = ev_sev.get(Severity.CRITICAL, 0),
    )

    al_sev_r = await db.execute(
        select(Alert.severity, func.count())
        .where(Alert.created_at >= since)
        .group_by(Alert.severity)
    )
    al_sev = dict(al_sev_r.all())
    alerts_by_severity = SeverityBreakdown(
        low      = al_sev.get(Severity.LOW, 0),
        medium   = al_sev.get(Severity.MEDIUM, 0),
        high     = al_sev.get(Severity.HIGH, 0),
        critical = al_sev.get(Severity.CRITICAL, 0),
    )

    events_over_time = await _events_timeseries(db, since, window_hours)

    top_ips_r = await db.execute(
        select(Event.source_ip, func.count().label("cnt"))
        .where(and_(Event.timestamp >= since, Event.source_ip.isnot(None)))
        .group_by(Event.source_ip)
        .order_by(desc("cnt"))
        .limit(10)
    )
    top_source_ips = [TopIP(source_ip=row[0], count=row[1]) for row in top_ips_r.all()]

    top_types_r = await db.execute(
        select(Event.event_type, func.count().label("cnt"))
        .where(Event.timestamp >= since)
        .group_by(Event.event_type)
        .order_by(desc("cnt"))
        .limit(10)
    )
    top_event_types = [TopEventType(event_type=row[0], count=row[1]) for row in top_types_r.all()]

    al_stat_r = await db.execute(
        select(Alert.status, func.count()).group_by(Alert.status)
    )
    alerts_by_status = {str(row[0].value): row[1] for row in al_stat_r.all()}

    return DashboardStats(
        total_events_24h    = total_events,
        total_alerts_24h    = total_alerts,
        open_alerts         = open_alerts,
        critical_alerts     = critical_alerts,
        blocked_ips         = blocked_ips,
        events_by_severity  = events_by_severity,
        alerts_by_severity  = alerts_by_severity,
        events_over_time    = events_over_time,
        top_source_ips      = top_source_ips,
        top_event_types     = top_event_types,
        alerts_by_status    = alerts_by_status,
    )


async def _events_timeseries(
    db: AsyncSession, since: datetime, window_hours: int
) -> list[TimeSeriesPoint]:

    result = await db.execute(
        select(Event.timestamp).where(Event.timestamp >= since).order_by(Event.timestamp)
    )
    timestamps = [row[0] for row in result.all()]

    buckets: dict[str, int] = defaultdict(int)
    for ts in timestamps:
        bucket = ts.strftime("%Y-%m-%dT%H:00")
        buckets[bucket] += 1

    current = since.replace(minute=0, second=0, microsecond=0)
    points  = []
    for _ in range(window_hours):
        key = current.strftime("%Y-%m-%dT%H:00")
        points.append(TimeSeriesPoint(timestamp=key, count=buckets.get(key, 0)))
        current += timedelta(hours=1)

    return points


@router.get("/events/timeseries", response_model=list[TimeSeriesPoint])
async def events_timeseries(
    hours: int         = Query(24, ge=1, le=168),
    db:    AsyncSession = Depends(get_db),
):
    since = datetime.utcnow() - timedelta(hours=hours)
    return await _events_timeseries(db, since, hours)


@router.get("/top-ips", response_model=list[TopIP])
async def top_ips(
    hours: int         = Query(24, ge=1, le=168),
    limit: int         = Query(10, ge=1, le=50),
    db:    AsyncSession = Depends(get_db),
):
    since  = datetime.utcnow() - timedelta(hours=hours)
    result = await db.execute(
        select(Event.source_ip, func.count().label("cnt"))
        .where(and_(Event.timestamp >= since, Event.source_ip.isnot(None)))
        .group_by(Event.source_ip)
        .order_by(desc("cnt"))
        .limit(limit)
    )
    return [TopIP(source_ip=r[0], count=r[1]) for r in result.all()]


@router.get("/top-event-types", response_model=list[TopEventType])
async def top_event_types(
    hours: int         = Query(24, ge=1, le=168),
    limit: int         = Query(10, ge=1, le=50),
    db:    AsyncSession = Depends(get_db),
):
    since  = datetime.utcnow() - timedelta(hours=hours)
    result = await db.execute(
        select(Event.event_type, func.count().label("cnt"))
        .where(Event.timestamp >= since)
        .group_by(Event.event_type)
        .order_by(desc("cnt"))
        .limit(limit)
    )
    return [TopEventType(event_type=r[0], count=r[1]) for r in result.all()]


@router.get("/mitre")
async def mitre_coverage(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Alert.mitre_tactic, Alert.mitre_technique, func.count().label("cnt"))
        .where(Alert.mitre_tactic.isnot(None))
        .group_by(Alert.mitre_tactic, Alert.mitre_technique)
        .order_by(desc("cnt"))
    )
    rows = result.all()
    return [{"tactic": r[0], "technique": r[1], "count": r[2]} for r in rows]
