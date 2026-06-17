

import re
import json
import logging
from datetime import datetime
from typing import Optional
from dateutil import parser as dateparser

logger = logging.getLogger(__name__)


PATTERNS = {
    "ssh_failed_login": re.compile(
        r"Failed password for (?:invalid user )?(?P<username>\S+) from (?P<source_ip>[\d.]+)"
    ),
    "ssh_accepted_login": re.compile(
        r"Accepted (?:password|publickey) for (?P<username>\S+) from (?P<source_ip>[\d.]+)"
    ),
    "ssh_invalid_user": re.compile(
        r"Invalid user (?P<username>\S+) from (?P<source_ip>[\d.]+)"
    ),
    "sudo_usage": re.compile(
        r"(?P<username>\S+) : .*COMMAND=(?P<command>.+)"
    ),
    "sudo_failed": re.compile(
        r"sudo: (?P<username>\S+) : authentication failure"
    ),
    "user_created": re.compile(
        r"new user: name=(?P<username>\S+)"
    ),
    "user_deleted": re.compile(
        r"delete user '(?P<username>\S+)'"
    ),
    "user_login": re.compile(
        r"session opened for user (?P<username>\S+)"
    ),
    "web_error": re.compile(
        r'(?P<source_ip>[\d.]+) .+ "(?P<method>GET|POST|PUT|DELETE|HEAD) (?P<path>\S+) HTTP/[\d.]+" (?P<status>[45]\d{2})'
    ),
    "port_scan": re.compile(
        r"SRC=(?P<source_ip>[\d.]+) DST=(?P<dest_ip>[\d.]+) .+ DPT=(?P<dest_port>\d+)"
    ),
    "ip_banned": re.compile(
        r"Ban (?P<source_ip>[\d.]+)"
    ),
    "oom_kill": re.compile(
        r"Out of memory: Killed process (?P<pid>\d+) \((?P<process>\S+)\)"
    ),
}

EVENT_META = {
    "ssh_failed_login":   {"category": "authentication", "severity": "medium"},
    "ssh_accepted_login": {"category": "authentication", "severity": "low"},
    "ssh_invalid_user":   {"category": "authentication", "severity": "medium"},
    "sudo_usage":         {"category": "privilege_escalation", "severity": "low"},
    "sudo_failed":        {"category": "privilege_escalation", "severity": "high"},
    "user_created":       {"category": "account_management", "severity": "medium"},
    "user_deleted":       {"category": "account_management", "severity": "high"},
    "user_login":         {"category": "authentication", "severity": "low"},
    "web_error":          {"category": "web", "severity": "low"},
    "port_scan":          {"category": "network", "severity": "medium"},
    "ip_banned":          {"category": "network", "severity": "medium"},
    "oom_kill":           {"category": "system", "severity": "medium"},
}


SYSLOG_TS = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<process>\S+):\s+(?P<msg>.+)$"
)
ISO_TS = re.compile(r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})")


def extract_timestamp(line: str) -> tuple[Optional[datetime], str]:
    m = SYSLOG_TS.match(line)
    if m:
        try:
            ts = dateparser.parse(m.group("ts"), default=datetime.now().replace(hour=0, minute=0, second=0))
            return ts, m.group("msg")
        except Exception:
            pass
    m = ISO_TS.search(line)
    if m:
        try:
            return dateparser.parse(m.group("ts")), line
        except Exception:
            pass
    return datetime.utcnow(), line



def parse_log_line(raw: str, log_source: str = "unknown") -> Optional[dict]:

    raw = raw.strip()
    if not raw:
        return None

    if raw.startswith("{"):
        return _parse_json_log(raw, log_source)

    timestamp, message = extract_timestamp(raw)

    for event_type, pattern in PATTERNS.items():
        m = pattern.search(message)
        if m:
            groups = m.groupdict()
            meta = EVENT_META.get(event_type, {"category": "unknown", "severity": "low"})
            event = {
                "timestamp": timestamp.isoformat(),
                "event_type": event_type,
                "category": meta["category"],
                "severity": meta["severity"],
                "source_ip": groups.get("source_ip"),
                "dest_ip": groups.get("dest_ip"),
                "dest_port": int(groups["dest_port"]) if groups.get("dest_port") else None,
                "username": groups.get("username"),
                "message": message[:500],
                "raw_log": raw[:1000],
                "log_source": log_source,
                "extra": {k: v for k, v in groups.items()
                          if k not in ("source_ip", "dest_ip", "dest_port", "username") and v},
            }
            return event

    return {
        "timestamp": timestamp.isoformat(),
        "event_type": "generic",
        "category": "unknown",
        "severity": "low",
        "source_ip": None,
        "dest_ip": None,
        "dest_port": None,
        "username": None,
        "message": message[:500],
        "raw_log": raw[:1000],
        "log_source": log_source,
        "extra": {},
    }


def _parse_json_log(raw: str, log_source: str) -> Optional[dict]:
    try:
        data = json.loads(raw)
        return {
            "timestamp": data.get("timestamp", data.get("time", datetime.utcnow().isoformat())),
            "event_type": data.get("event_type", data.get("type", "json_log")),
            "category": data.get("category", "application"),
            "severity": data.get("severity", data.get("level", "low")),
            "source_ip": data.get("source_ip", data.get("ip", data.get("remote_addr"))),
            "dest_ip": data.get("dest_ip"),
            "dest_port": data.get("dest_port"),
            "username": data.get("username", data.get("user")),
            "message": data.get("message", data.get("msg", raw[:200])),
            "raw_log": raw[:1000],
            "log_source": log_source,
            "extra": {k: v for k, v in data.items()
                      if k not in ("timestamp", "time", "event_type", "type",
                                   "category", "severity", "source_ip", "ip",
                                   "dest_ip", "dest_port", "username", "user",
                                   "message", "msg")},
        }
    except json.JSONDecodeError:
        return None
