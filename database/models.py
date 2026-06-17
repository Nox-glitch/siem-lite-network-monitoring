"""
SIEM Lite - Database Models
SQLAlchemy ORM models for events, alerts, and rules.
"""

from datetime import datetime
from enum import Enum as PyEnum
from sqlalchemy import (
    Column, String, Integer, Float, Boolean,
    DateTime, Text, JSON, Enum, ForeignKey, Index
)
from sqlalchemy.orm import DeclarativeBase, relationship
from sqlalchemy.sql import func


class Base(DeclarativeBase):
    pass


class Severity(str, PyEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(str, PyEnum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class Event(Base):
    """Normalized security event from any log source."""
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), default=func.now(), index=True)
    source_ip = Column(String(45), index=True)         # IPv4/IPv6
    dest_ip = Column(String(45), nullable=True)
    source_port = Column(Integer, nullable=True)
    dest_port = Column(Integer, nullable=True)
    hostname = Column(String(255), nullable=True)
    event_type = Column(String(100), index=True)        # e.g. ssh_failed_login
    category = Column(String(50), index=True)           # authentication, network, system
    severity = Column(Enum(Severity), default=Severity.LOW, index=True)
    message = Column(Text)
    raw_log = Column(Text)
    log_source = Column(String(100))                    # auth.log, syslog, etc.
    username = Column(String(100), nullable=True)
    country = Column(String(100), nullable=True)
    city = Column(String(100), nullable=True)
    threat_score = Column(Float, default=0.0)           # 0-100 from threat intel
    extra = Column(JSON, default=dict)                  # flexible additional fields

    alerts = relationship("Alert", back_populates="event")

    __table_args__ = (
        Index("ix_events_timestamp_severity", "timestamp", "severity"),
        Index("ix_events_source_ip_type", "source_ip", "event_type"),
    )


class Alert(Base):
    """Alert generated when a detection rule fires."""
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime(timezone=True), default=func.now(), index=True)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    rule_name = Column(String(200), index=True)
    rule_id = Column(String(100))
    severity = Column(Enum(Severity), index=True)
    status = Column(Enum(AlertStatus), default=AlertStatus.OPEN, index=True)
    title = Column(String(300))
    description = Column(Text)
    source_ip = Column(String(45), index=True)
    event_count = Column(Integer, default=1)
    event_id = Column(Integer, ForeignKey("events.id"), nullable=True)
    playbook_triggered = Column(String(200), nullable=True)
    playbook_result = Column(JSON, nullable=True)
    analyst_notes = Column(Text, nullable=True)
    mitre_tactic = Column(String(100), nullable=True)   # e.g. TA0006 - Credential Access
    mitre_technique = Column(String(100), nullable=True) # e.g. T1110 - Brute Force
    tags = Column(JSON, default=list)

    event = relationship("Event", back_populates="alerts")


class DetectionRule(Base):
    """User-managed detection rules (also loaded from rules.yaml)."""
    __tablename__ = "detection_rules"

    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(String(100), unique=True, index=True)
    name = Column(String(200))
    description = Column(Text)
    enabled = Column(Boolean, default=True)
    severity = Column(Enum(Severity))
    category = Column(String(50))
    condition_type = Column(String(50))                 # threshold, pattern, sequence
    condition_config = Column(JSON)                     # rule params
    playbook = Column(String(100), nullable=True)       # which playbook to run
    mitre_tactic = Column(String(100), nullable=True)
    mitre_technique = Column(String(100), nullable=True)
    created_at = Column(DateTime(timezone=True), default=func.now())
    fire_count = Column(Integer, default=0)             # how many times it triggered
    last_fired = Column(DateTime(timezone=True), nullable=True)


class BlockedIP(Base):
    """IPs that have been auto-blocked by playbooks."""
    __tablename__ = "blocked_ips"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(45), unique=True, index=True)
    reason = Column(String(300))
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=True)
    blocked_at = Column(DateTime(timezone=True), default=func.now())
    unblocked_at = Column(DateTime(timezone=True), nullable=True)
    is_active = Column(Boolean, default=True)
    auto_unblock_after = Column(Integer, nullable=True)  # minutes


# ── Network Monitoring Models ─────────────────────────────────────────────────

class DeviceType(str, PyEnum):
    ROUTER   = "router"
    SWITCH   = "switch"
    FIREWALL = "firewall"
    ACCESS_POINT = "access_point"
    SERVER   = "server"
    OTHER    = "other"


class DeviceStatus(str, PyEnum):
    ONLINE  = "online"
    OFFLINE = "offline"
    WARNING = "warning"
    CRITICAL = "critical"


class NetworkDevice(Base):
    """Registered network device (router, switch, firewall, AP)."""
    __tablename__ = "network_devices"

    id          = Column(Integer, primary_key=True, index=True)
    name        = Column(String(100), unique=True, index=True)   # e.g. "Core Router 1"
    ip_address  = Column(String(45), unique=True, index=True)
    mac_address = Column(String(17), nullable=True)
    device_type = Column(Enum(DeviceType), default=DeviceType.OTHER)
    vendor      = Column(String(100), nullable=True)             # Cisco, Juniper, etc.
    model       = Column(String(100), nullable=True)
    location    = Column(String(200), nullable=True)             # "Server Room A, Rack 3"
    status      = Column(Enum(DeviceStatus), default=DeviceStatus.ONLINE)
    is_monitored = Column(Boolean, default=True)
    added_at    = Column(DateTime(timezone=True), default=func.now())
    last_seen   = Column(DateTime(timezone=True), nullable=True)
    uptime_seconds = Column(Integer, default=0)
    notes       = Column(Text, nullable=True)

    metrics    = relationship("DeviceMetric",    back_populates="device",
                              cascade="all, delete-orphan")
    thresholds = relationship("DeviceThreshold", back_populates="device",
                              cascade="all, delete-orphan", uselist=False)


class DeviceMetric(Base):
    """
    Point-in-time metric snapshot for a network device.
    Polled every 30s by the metric collector worker.
    """
    __tablename__ = "device_metrics"

    id              = Column(Integer, primary_key=True, index=True)
    device_id       = Column(Integer, ForeignKey("network_devices.id"), index=True)
    timestamp       = Column(DateTime(timezone=True), default=func.now(), index=True)

    # Thermal
    temperature_c   = Column(Float, nullable=True)   # degrees Celsius

    # Compute
    cpu_percent     = Column(Float, nullable=True)   # 0-100
    memory_percent  = Column(Float, nullable=True)   # 0-100

    # Network throughput (on primary interface)
    bandwidth_in_mbps  = Column(Float, nullable=True)
    bandwidth_out_mbps = Column(Float, nullable=True)
    packets_in         = Column(Integer, nullable=True)
    packets_out        = Column(Integer, nullable=True)
    error_count        = Column(Integer, default=0)
    dropped_packets    = Column(Integer, default=0)

    # Availability
    latency_ms      = Column(Float, nullable=True)   # ICMP round-trip
    is_online       = Column(Boolean, default=True)

    device = relationship("NetworkDevice", back_populates="metrics")

    __table_args__ = (
        Index("ix_device_metrics_device_ts", "device_id", "timestamp"),
    )


class DeviceThreshold(Base):
    """
    Per-device alert thresholds. A notification fires when any
    metric crosses its threshold for threshold_duration_seconds.
    """
    __tablename__ = "device_thresholds"

    id        = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("network_devices.id"),
                       unique=True, index=True)

    # Temperature thresholds (°C)
    temp_warn     = Column(Float, default=60.0)   # yellow warning
    temp_critical = Column(Float, default=80.0)   # red critical + notify

    # CPU thresholds (%)
    cpu_warn      = Column(Float, default=70.0)
    cpu_critical  = Column(Float, default=90.0)

    # Memory thresholds (%)
    mem_warn      = Column(Float, default=75.0)
    mem_critical  = Column(Float, default=90.0)

    # Bandwidth thresholds (Mbps)
    bandwidth_warn     = Column(Float, default=800.0)
    bandwidth_critical = Column(Float, default=950.0)

    # Latency thresholds (ms)
    latency_warn     = Column(Float, default=100.0)
    latency_critical = Column(Float, default=500.0)

    # How long a metric must stay over threshold before alerting
    duration_seconds = Column(Integer, default=60)

    # Notification channels
    notify_slack = Column(Boolean, default=True)
    notify_email = Column(Boolean, default=True)

    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    device = relationship("NetworkDevice", back_populates="thresholds")


class DeviceNotification(Base):
    """
    Fired when a device metric crosses a threshold.
    Separate from security alerts — purely operational.
    """
    __tablename__ = "device_notifications"

    id          = Column(Integer, primary_key=True, index=True)
    device_id   = Column(Integer, ForeignKey("network_devices.id"), index=True)
    created_at  = Column(DateTime(timezone=True), default=func.now(), index=True)
    metric      = Column(String(50))           # temperature_c, cpu_percent, etc.
    value       = Column(Float)                # actual reading
    threshold   = Column(Float)                # threshold that was crossed
    level       = Column(String(20))           # warn | critical
    message     = Column(String(300))
    acknowledged = Column(Boolean, default=False)
    ack_at      = Column(DateTime(timezone=True), nullable=True)
