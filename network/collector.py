"""
SIEM Lite - Network Device Metric Collector
Polls registered devices every 30s, stores metrics, checks thresholds,
fires DeviceNotification records + pushes to Redis for live dashboard.

In production: replace _simulate_metrics() with real SNMP/SSH polling.
Supports: SNMP v2c/v3, ping latency, REST APIs (Cisco IOS-XE, Junos).
"""

import os
import json
import time
import math
import random
import logging
import threading
from datetime import datetime, timedelta

import redis
from sqlalchemy.orm import Session
from sqlalchemy import create_engine, select

from database.models import (
    NetworkDevice, DeviceMetric, DeviceThreshold,
    DeviceNotification, DeviceStatus
)
from database.connection import create_tables_sync

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

REDIS_URL    = os.getenv("REDIS_URL",    "redis://localhost:6379")
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://siem:siempass@localhost:5432/siemdb")
POLL_INTERVAL = int(os.getenv("METRIC_POLL_INTERVAL", "30"))   # seconds

REDIS_METRICS_CHANNEL = "siem:device_metrics"
REDIS_NOTIF_CHANNEL   = "siem:device_notifications"

# ── Metric simulation (replace with SNMP in production) ───────────────────────

# Per-device simulated "base" state so metrics look realistic over time
_device_state: dict[int, dict] = {}


def _get_state(device_id: int, device_type: str) -> dict:
    if device_id not in _device_state:
        # Routers run hotter and busier than switches by default
        is_router = "router" in device_type.lower()
        _device_state[device_id] = {
            "temp_base":  55.0 if is_router else 42.0,
            "cpu_base":   35.0 if is_router else 15.0,
            "mem_base":   50.0 if is_router else 30.0,
            "bw_base":    200.0 if is_router else 80.0,
            "tick":       0,
        }
    return _device_state[device_id]


def _simulate_metrics(device: NetworkDevice) -> dict:
    """
    Generate realistic simulated metrics with sinusoidal load patterns
    and occasional spikes. Replace with SNMP/SSH calls in production.
    """
    s    = _get_state(device.id, device.device_type.value)
    tick = s["tick"]
    s["tick"] += 1

    # Sinusoidal base + random noise + occasional spike
    def wave(base, amplitude=8, noise=3, spike_prob=0.05, spike_size=20):
        val = base + amplitude * math.sin(tick / 10) + random.uniform(-noise, noise)
        if random.random() < spike_prob:
            val += random.uniform(spike_size * 0.5, spike_size)
        return round(max(0, val), 1)

    cpu   = min(100, wave(s["cpu_base"],  amplitude=12, noise=4))
    mem   = min(100, wave(s["mem_base"],  amplitude=8,  noise=2))
    temp  = wave(s["temp_base"], amplitude=6, noise=1.5, spike_prob=0.03, spike_size=15)
    bw_in = max(0, wave(s["bw_base"],    amplitude=50, noise=10))
    bw_out= max(0, bw_in * random.uniform(0.3, 0.9))

    return {
        "temperature_c":      temp,
        "cpu_percent":        cpu,
        "memory_percent":     mem,
        "bandwidth_in_mbps":  round(bw_in,  2),
        "bandwidth_out_mbps": round(bw_out, 2),
        "packets_in":         int(bw_in  * 1000 * random.uniform(0.8, 1.2)),
        "packets_out":        int(bw_out * 1000 * random.uniform(0.8, 1.2)),
        "error_count":        random.randint(0, 2),
        "dropped_packets":    random.randint(0, 1),
        "latency_ms":         round(random.uniform(0.5, 8.0), 2),
        "is_online":          True,
    }


# ── Threshold checking ─────────────────────────────────────────────────────────

METRIC_LABELS = {
    "temperature_c":      "Temperature",
    "cpu_percent":        "CPU Usage",
    "memory_percent":     "Memory Usage",
    "bandwidth_in_mbps":  "Inbound Bandwidth",
    "latency_ms":         "Latency",
}

METRIC_UNITS = {
    "temperature_c":     "°C",
    "cpu_percent":       "%",
    "memory_percent":    "%",
    "bandwidth_in_mbps": " Mbps",
    "latency_ms":        " ms",
}


def _check_thresholds(
    session: Session,
    device: NetworkDevice,
    metrics: dict,
    r: redis.Redis,
):
    thresh = device.thresholds
    if not thresh:
        return

    checks = [
        ("temperature_c",     thresh.temp_warn,      thresh.temp_critical),
        ("cpu_percent",       thresh.cpu_warn,        thresh.cpu_critical),
        ("memory_percent",    thresh.mem_warn,        thresh.mem_critical),
        ("bandwidth_in_mbps", thresh.bandwidth_warn,  thresh.bandwidth_critical),
        ("latency_ms",        thresh.latency_warn,    thresh.latency_critical),
    ]

    for metric_key, warn_val, crit_val in checks:
        value = metrics.get(metric_key)
        if value is None:
            continue

        level = None
        threshold = None
        if value >= crit_val:
            level, threshold = "critical", crit_val
        elif value >= warn_val:
            level, threshold = "warn", warn_val

        if not level:
            continue

        label = METRIC_LABELS.get(metric_key, metric_key)
        unit  = METRIC_UNITS.get(metric_key, "")
        msg   = (
            f"{device.name} — {label} is {value}{unit} "
            f"({'≥' if level == 'critical' else '≥'} {threshold}{unit} {level} threshold)"
        )

        # Dedup: skip if same metric already has an unacknowledged notif in last 5 min
        recent = session.query(DeviceNotification).filter(
            DeviceNotification.device_id    == device.id,
            DeviceNotification.metric       == metric_key,
            DeviceNotification.acknowledged == False,
            DeviceNotification.created_at   >= datetime.utcnow() - timedelta(minutes=5),
        ).first()

        if recent:
            continue

        notif = DeviceNotification(
            device_id  = device.id,
            metric     = metric_key,
            value      = value,
            threshold  = threshold,
            level      = level,
            message    = msg,
        )
        session.add(notif)
        session.flush()

        # Update device status
        if level == "critical":
            device.status = DeviceStatus.CRITICAL
        elif device.status == DeviceStatus.ONLINE:
            device.status = DeviceStatus.WARNING

        # Publish to Redis for live dashboard
        payload = {
            "type":       "device_notification",
            "notif_id":   notif.id,
            "device_id":  device.id,
            "device_name": device.name,
            "metric":     metric_key,
            "value":      value,
            "threshold":  threshold,
            "level":      level,
            "message":    msg,
            "timestamp":  datetime.utcnow().isoformat(),
        }
        r.publish(REDIS_NOTIF_CHANNEL, json.dumps(payload))
        logger.warning(f"🌡️  THRESHOLD [{level.upper()}] {msg}")


# ── Main polling loop ─────────────────────────────────────────────────────────

def poll_once(session: Session, r: redis.Redis):
    devices = session.query(NetworkDevice).filter(
        NetworkDevice.is_monitored == True
    ).all()

    if not devices:
        return

    now = datetime.utcnow()
    for device in devices:
        try:
            raw = _simulate_metrics(device)

            metric = DeviceMetric(
                device_id          = device.id,
                timestamp          = now,
                **raw,
            )
            session.add(metric)

            # Update last_seen + uptime
            device.last_seen      = now
            device.uptime_seconds = (device.uptime_seconds or 0) + POLL_INTERVAL
            if raw.get("is_online") and device.status == DeviceStatus.OFFLINE:
                device.status = DeviceStatus.ONLINE

            # Check thresholds
            _check_thresholds(session, device, raw, r)

            # Publish metric for live chart updates
            r.publish(REDIS_METRICS_CHANNEL, json.dumps({
                "device_id":   device.id,
                "device_name": device.name,
                "timestamp":   now.isoformat(),
                **raw,
            }))

        except Exception as e:
            logger.error(f"Error polling device {device.name}: {e}")

    session.commit()

    # Purge metrics older than 24h to keep DB lean
    cutoff = now - timedelta(hours=24)
    session.query(DeviceMetric).filter(DeviceMetric.timestamp < cutoff).delete()
    session.commit()


def run_collector():
    create_tables_sync()
    r      = redis.from_url(REDIS_URL)
    engine = create_engine(DATABASE_URL, pool_size=3)

    logger.info(f"📡 Metric collector started — polling every {POLL_INTERVAL}s")

    while True:
        try:
            with Session(engine) as session:
                poll_once(session, r)
        except Exception as e:
            logger.exception(f"Collector error: {e}")
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    run_collector()
