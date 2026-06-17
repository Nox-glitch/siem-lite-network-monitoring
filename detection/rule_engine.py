
import os
import json
import time
import logging
from datetime import datetime, timedelta
from collections import defaultdict, deque
from typing import Any

import yaml
import redis
from sqlalchemy.orm import Session
from sqlalchemy import create_engine

from database.models import Alert, Event, DetectionRule, Severity, AlertStatus
from database.connection import create_tables_sync

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://siem:siempass@localhost:5432/siemdb")
RULES_PATH = os.path.join(os.path.dirname(__file__), "rules.yaml")
REDIS_EVENTS_QUEUE = "siem:events:queue"
REDIS_ALERTS_CHANNEL = "siem:alerts"



class SlidingWindow:

    def __init__(self):
        self._windows: dict[tuple, deque] = defaultdict(deque)

    def add(self, rule_id: str, group_value: str, window_seconds: int) -> int:
        key = (rule_id, group_value)
        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=window_seconds)
        q = self._windows[key]
        q.append(now)
        # Purge old entries
        while q and q[0] < cutoff:
            q.popleft()
        return len(q)


sliding_windows = SlidingWindow()



def load_rules() -> list[dict]:
    with open(RULES_PATH) as f:
        data = yaml.safe_load(f)
    rules = [r for r in data.get("rules", []) if r.get("enabled", True)]
    logger.info(f"Loaded {len(rules)} detection rules")
    return rules



def evaluate_threshold(rule: dict, event: dict) -> bool:
    cond = rule["condition"]
    if event.get("event_type") != cond["event_type"]:
        return False
    group_by = cond.get("group_by", "source_ip")
    group_value = event.get(group_by, "unknown")
    count = sliding_windows.add(rule["id"], group_value, cond["window_seconds"])
    return count >= cond["count"]


def evaluate_pattern(rule: dict, event: dict) -> bool:
    cond = rule["condition"]
    if event.get("event_type") != cond["event_type"]:
        return False
    # Optional field match
    if "field" in cond:
        field_val = str(event.get(cond["field"], event.get("extra", {}).get(cond["field"], "")))
        if "value" in cond:
            if field_val != str(cond["value"]):
                return False
        elif "contains_any" in cond:
            if not any(needle in field_val for needle in cond["contains_any"]):
                return False
        elif "contains" in cond:
            if cond["contains"] not in field_val:
                return False
    return True


EVALUATORS = {
    "threshold": evaluate_threshold,
    "pattern": evaluate_pattern,
}



def store_event(session: Session, event: dict) -> Event:
    db_event = Event(
        timestamp=datetime.fromisoformat(event["timestamp"]) if isinstance(event["timestamp"], str) else event["timestamp"],
        source_ip=event.get("source_ip"),
        dest_ip=event.get("dest_ip"),
        dest_port=event.get("dest_port"),
        hostname=event.get("hostname"),
        event_type=event["event_type"],
        category=event.get("category", "unknown"),
        severity=Severity(event.get("severity", "low")),
        message=event.get("message", ""),
        raw_log=event.get("raw_log", ""),
        log_source=event.get("log_source", "unknown"),
        username=event.get("username"),
        extra=event.get("extra", {}),
    )
    session.add(db_event)
    session.flush()
    return db_event


def create_alert(session: Session, rule: dict, event: dict, db_event: Event,
                 redis_client: redis.Redis):

    existing = session.query(Alert).filter(
        Alert.rule_id == rule["id"],
        Alert.source_ip == event.get("source_ip"),
        Alert.status == AlertStatus.OPEN,
        Alert.created_at >= datetime.utcnow() - timedelta(minutes=10),
    ).first()

    if existing:
        existing.event_count += 1
        session.flush()
        return existing

    alert = Alert(
        rule_name=rule["name"],
        rule_id=rule["id"],
        severity=Severity(rule["severity"]),
        status=AlertStatus.OPEN,
        title=f"[{rule['severity'].upper()}] {rule['name']}",
        description=rule.get("description", ""),
        source_ip=event.get("source_ip"),
        event_id=db_event.id,
        playbook_triggered=rule.get("playbook"),
        mitre_tactic=rule.get("mitre_tactic"),
        mitre_technique=rule.get("mitre_technique"),
        tags=rule.get("tags", []),
    )
    session.add(alert)
    session.flush()

    payload = {
        "alert_id": alert.id,
        "rule_id": rule["id"],
        "rule_name": rule["name"],
        "severity": rule["severity"],
        "source_ip": event.get("source_ip"),
        "playbook": rule.get("playbook"),
        "event": event,
    }
    redis_client.publish(REDIS_ALERTS_CHANNEL, json.dumps(payload))
    logger.info(f"🚨 ALERT [{rule['severity'].upper()}]: {rule['name']} — {event.get('source_ip')}")
    return alert



def run_engine():
    create_tables_sync()
    r = redis.from_url(REDIS_URL)
    engine = create_engine(DATABASE_URL, pool_size=5)
    rules = load_rules()

    logger.info("Detection engine running, waiting for events...")

    while True:
        try:
            item = r.brpop(REDIS_EVENTS_QUEUE, timeout=1)
            if not item:
                continue

            _, payload = item
            event = json.loads(payload)

            with Session(engine) as session:
                db_event = store_event(session, event)

                for rule in rules:
                    evaluator = EVALUATORS.get(rule["condition_type"])
                    if not evaluator:
                        continue
                    if evaluator(rule, event):
                        create_alert(session, rule, event, db_event, r)

                session.commit()

        except redis.ConnectionError as e:
            logger.error(f"Redis connection error: {e}, retrying in 5s")
            time.sleep(5)
        except Exception as e:
            logger.exception(f"Engine error: {e}")
            time.sleep(1)


if __name__ == "__main__":
    run_engine()
