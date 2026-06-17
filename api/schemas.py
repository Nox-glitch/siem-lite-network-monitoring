
#request or response models for all API endpoints.


from datetime import datetime
from typing import Optional, Any
from pydantic import BaseModel, Field
from database.models import Severity, AlertStatus


# ── Event schemas ─────────────────────────────────────────────────────────────

class EventOut(BaseModel):
    id:          int
    timestamp:   datetime
    source_ip:   Optional[str]
    dest_ip:     Optional[str]
    dest_port:   Optional[int]
    hostname:    Optional[str]
    event_type:  str
    category:    str
    severity:    Severity
    message:     str
    log_source:  str
    username:    Optional[str]
    country:     Optional[str]
    city:        Optional[str]
    threat_score: float
    extra:       dict

    model_config = {"from_attributes": True}


class EventListResponse(BaseModel):
    total:  int
    page:   int
    size:   int
    items:  list[EventOut]


#alert schemas

class AlertOut(BaseModel):
    id:                  int
    created_at:          datetime
    updated_at:          Optional[datetime]
    rule_name:           str
    rule_id:             str
    severity:            Severity
    status:              AlertStatus
    title:               str
    description:         str
    source_ip:           Optional[str]
    event_count:         int
    event_id:            Optional[int]
    playbook_triggered:  Optional[str]
    playbook_result:     Optional[dict]
    analyst_notes:       Optional[str]
    mitre_tactic:        Optional[str]
    mitre_technique:     Optional[str]
    tags:                list

    model_config = {"from_attributes": True}


class AlertUpdateRequest(BaseModel):
    status:        Optional[AlertStatus] = None
    analyst_notes: Optional[str]        = None


class AlertListResponse(BaseModel):
    total:  int
    page:   int
    size:   int
    items:  list[AlertOut]


# stats schemas

class SeverityBreakdown(BaseModel):
    low:      int = 0
    medium:   int = 0
    high:     int = 0
    critical: int = 0


class TimeSeriesPoint(BaseModel):
    timestamp: str
    count:     int


class TopIP(BaseModel):
    source_ip: str
    count:     int


class TopEventType(BaseModel):
    event_type: str
    count:      int


class DashboardStats(BaseModel):
    total_events_24h:    int
    total_alerts_24h:    int
    open_alerts:         int
    critical_alerts:     int
    blocked_ips:         int
    events_by_severity:  SeverityBreakdown
    alerts_by_severity:  SeverityBreakdown
    events_over_time:    list[TimeSeriesPoint]
    top_source_ips:      list[TopIP]
    top_event_types:     list[TopEventType]
    alerts_by_status:    dict[str, int]


#rule schemas
class RuleOut(BaseModel):
    id:               int
    rule_id:          str
    name:             str
    description:      Optional[str]
    enabled:          bool
    severity:         Severity
    category:         str
    condition_type:   str
    condition_config: dict
    playbook:         Optional[str]
    mitre_tactic:     Optional[str]
    mitre_technique:  Optional[str]
    fire_count:       int
    last_fired:       Optional[datetime]

    model_config = {"from_attributes": True}


class RuleUpdateRequest(BaseModel):
    enabled:     Optional[bool] = None
    severity:    Optional[Severity] = None
    description: Optional[str] = None


#blocked ip schemas
class BlockedIPOut(BaseModel):
    id:                 int
    ip_address:         str
    reason:             str
    alert_id:           Optional[int]
    blocked_at:         datetime
    unblocked_at:       Optional[datetime]
    is_active:          bool
    auto_unblock_after: Optional[int]

    model_config = {"from_attributes": True}


class BlockedIPCreate(BaseModel):
    ip_address:         str = Field(..., description="IP to block, e.g. 1.2.3.4")
    reason:             str = Field(..., description="Why this IP is being blocked")
    auto_unblock_after: Optional[int] = Field(None, description="Minutes until auto-unblock (None = never)")
