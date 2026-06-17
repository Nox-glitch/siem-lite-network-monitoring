
import pytest
import pytest_asyncio
from datetime import datetime, timedelta
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from database.models import Base, Event, Alert, DetectionRule, BlockedIP, Severity, AlertStatus
from database.connection import get_db
from api.main import app


TEST_DB_URL = "sqlite+aiosqlite:///:memory:"
test_engine = create_async_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestSessionLocal = async_sessionmaker(test_engine, expire_on_commit=False)


async def override_get_db():
    async with TestSessionLocal() as session:
        yield session
        await session.commit()


app.dependency_overrides[get_db] = override_get_db


@pytest_asyncio.fixture(autouse=True)
async def setup_db():
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest_asyncio.fixture
async def db():
    async with TestSessionLocal() as session:
        yield session
        await session.commit()



async def seed_event(db: AsyncSession, **kwargs) -> Event:
    e = Event(
        timestamp  = kwargs.get("timestamp", datetime.utcnow()),
        source_ip  = kwargs.get("source_ip", "1.2.3.4"),
        event_type = kwargs.get("event_type", "ssh_failed_login"),
        category   = kwargs.get("category", "authentication"),
        severity   = kwargs.get("severity", Severity.MEDIUM),
        message    = kwargs.get("message", "Test event"),
        raw_log    = kwargs.get("raw_log", "raw"),
        log_source = kwargs.get("log_source", "test"),
        extra      = {},
    )
    db.add(e); await db.commit(); await db.refresh(e)
    return e


async def seed_alert(db: AsyncSession, **kwargs) -> Alert:
    a = Alert(
        rule_name   = kwargs.get("rule_name", "SSH Brute Force"),
        rule_id     = kwargs.get("rule_id", "SSH-001"),
        severity    = kwargs.get("severity", Severity.HIGH),
        status      = kwargs.get("status", AlertStatus.OPEN),
        title       = kwargs.get("title", "[HIGH] SSH Brute Force"),
        description = kwargs.get("description", "Test alert"),
        source_ip   = kwargs.get("source_ip", "1.2.3.4"),
        tags        = [],
    )
    db.add(a); await db.commit(); await db.refresh(a)
    return a



@pytest.mark.asyncio
async def test_root(client):
    r = await client.get("/")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_health(client):
    r = await client.get("/health")
    assert r.status_code == 200



@pytest.mark.asyncio
async def test_list_events_empty(client):
    r = await client.get("/api/events")
    assert r.status_code == 200
    data = r.json()
    assert data["total"] == 0
    assert data["items"] == []


@pytest.mark.asyncio
async def test_list_events_with_data(client, db):
    await seed_event(db, source_ip="10.0.0.1")
    await seed_event(db, source_ip="10.0.0.2", severity=Severity.HIGH)

    r = await client.get("/api/events")
    assert r.status_code == 200
    assert r.json()["total"] == 2


@pytest.mark.asyncio
async def test_filter_events_by_severity(client, db):
    await seed_event(db, severity=Severity.LOW)
    await seed_event(db, severity=Severity.HIGH)

    r = await client.get("/api/events?severity=high")
    assert r.status_code == 200
    assert r.json()["total"] == 1
    assert r.json()["items"][0]["severity"] == "high"


@pytest.mark.asyncio
async def test_filter_events_by_source_ip(client, db):
    await seed_event(db, source_ip="192.168.1.1")
    await seed_event(db, source_ip="10.10.10.10")

    r = await client.get("/api/events?source_ip=192.168.1.1")
    assert r.status_code == 200
    assert r.json()["total"] == 1


@pytest.mark.asyncio
async def test_get_event_by_id(client, db):
    event = await seed_event(db)
    r = await client.get(f"/api/events/{event.id}")
    assert r.status_code == 200
    assert r.json()["id"] == event.id


@pytest.mark.asyncio
async def test_get_event_not_found(client):
    r = await client.get("/api/events/99999")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_search_events(client, db):
    await seed_event(db, message="Failed password for root")
    await seed_event(db, message="Session opened for alice")

    r = await client.get("/api/events?search=root")
    assert r.status_code == 200
    assert r.json()["total"] == 1



@pytest.mark.asyncio
async def test_list_alerts_empty(client):
    r = await client.get("/api/alerts")
    assert r.status_code == 200
    assert r.json()["total"] == 0


@pytest.mark.asyncio
async def test_list_alerts_with_data(client, db):
    await seed_alert(db)
    r = await client.get("/api/alerts")
    assert r.status_code == 200
    assert r.json()["total"] == 1


@pytest.mark.asyncio
async def test_filter_alerts_by_status(client, db):
    await seed_alert(db, status=AlertStatus.OPEN)
    await seed_alert(db, status=AlertStatus.RESOLVED)

    r = await client.get("/api/alerts?status=open")
    assert r.status_code == 200
    assert r.json()["total"] == 1


@pytest.mark.asyncio
async def test_acknowledge_alert(client, db):
    alert = await seed_alert(db)
    r = await client.post(f"/api/alerts/{alert.id}/acknowledge")
    assert r.status_code == 200
    assert r.json()["status"] == "acknowledged"


@pytest.mark.asyncio
async def test_resolve_alert(client, db):
    alert = await seed_alert(db)
    r = await client.post(f"/api/alerts/{alert.id}/resolve")
    assert r.status_code == 200
    assert r.json()["status"] == "resolved"


@pytest.mark.asyncio
async def test_false_positive_alert(client, db):
    alert = await seed_alert(db)
    r = await client.post(f"/api/alerts/{alert.id}/false-positive")
    assert r.status_code == 200
    assert r.json()["status"] == "false_positive"


@pytest.mark.asyncio
async def test_update_alert_notes(client, db):
    alert = await seed_alert(db)
    r = await client.patch(f"/api/alerts/{alert.id}", json={"analyst_notes": "Investigated — benign"})
    assert r.status_code == 200
    assert r.json()["analyst_notes"] == "Investigated — benign"


@pytest.mark.asyncio
async def test_get_alert_not_found(client):
    r = await client.get("/api/alerts/99999")
    assert r.status_code == 404



@pytest.mark.asyncio
async def test_dashboard_stats_empty(client):
    r = await client.get("/api/stats/dashboard")
    assert r.status_code == 200
    data = r.json()
    assert data["total_events_24h"] == 0
    assert data["open_alerts"] == 0
    assert "events_over_time" in data
    assert "top_source_ips" in data


@pytest.mark.asyncio
async def test_dashboard_stats_counts(client, db):
    await seed_event(db, severity=Severity.HIGH)
    await seed_event(db, severity=Severity.CRITICAL)
    await seed_alert(db, severity=Severity.HIGH)

    r = await client.get("/api/stats/dashboard")
    assert r.status_code == 200
    data = r.json()
    assert data["total_events_24h"] == 2
    assert data["total_alerts_24h"] == 1
    assert data["open_alerts"] == 1


@pytest.mark.asyncio
async def test_top_ips(client, db):
    for _ in range(3):
        await seed_event(db, source_ip="5.5.5.5")
    await seed_event(db, source_ip="6.6.6.6")

    r = await client.get("/api/stats/top-ips")
    assert r.status_code == 200
    data = r.json()
    assert data[0]["source_ip"] == "5.5.5.5"
    assert data[0]["count"] == 3



@pytest.mark.asyncio
async def test_list_blocked_ips_empty(client):
    r = await client.get("/api/blocked-ips")
    assert r.status_code == 200
    assert r.json() == []


@pytest.mark.asyncio
async def test_block_and_unblock_ip(client):
    # Block
    r = await client.post("/api/blocked-ips", json={"ip_address": "9.9.9.9", "reason": "Test block"})
    assert r.status_code == 201
    assert r.json()["ip_address"] == "9.9.9.9"
    assert r.json()["is_active"] is True

    # List — should appear
    r = await client.get("/api/blocked-ips")
    assert len(r.json()) == 1

    # Unblock
    r = await client.delete("/api/blocked-ips/9.9.9.9")
    assert r.status_code == 200
    assert r.json()["status"] == "unblocked"

    # List — should be gone (active_only=True default)
    r = await client.get("/api/blocked-ips")
    assert r.json() == []


@pytest.mark.asyncio
async def test_block_duplicate_raises_409(client):
    await client.post("/api/blocked-ips", json={"ip_address": "8.8.8.8", "reason": "First"})
    r = await client.post("/api/blocked-ips", json={"ip_address": "8.8.8.8", "reason": "Duplicate"})
    assert r.status_code == 409
