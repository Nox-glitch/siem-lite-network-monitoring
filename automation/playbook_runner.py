

import os
import json
import time
import logging
import importlib
from datetime import datetime

import redis
from sqlalchemy.orm import Session
from sqlalchemy import create_engine

from database.models import Alert
from database.connection import create_tables_sync

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

REDIS_URL      = os.getenv("REDIS_URL", "redis://localhost:6379")
DATABASE_URL   = os.getenv("DATABASE_URL", "postgresql://siem:siempass@localhost:5432/siemdb")
ALERTS_CHANNEL = "siem:alerts"


PLAYBOOK_REGISTRY = {
    "block_ip_and_notify": "automation.playbooks.block_ip",
    "notify_only":         "automation.playbooks.notify_slack",
    "create_ticket":       "automation.playbooks.create_ticket",
}


def run_playbook(name: str, alert_payload: dict) -> dict:

    module_path = PLAYBOOK_REGISTRY.get(name)
    if not module_path:
        logger.warning(f"Unknown playbook: {name}")
        return {"status": "error", "message": f"Unknown playbook: {name}"}

    try:
        module = importlib.import_module(module_path)
        result = module.execute(alert_payload)
        logger.info(f"✅ Playbook '{name}' completed: {result.get('status')}")
        return result
    except Exception as e:
        logger.exception(f"Playbook '{name}' failed: {e}")
        return {"status": "error", "message": str(e)}


def save_playbook_result(session: Session, alert_id: int, playbook: str, result: dict):

    alert = session.query(Alert).filter(Alert.id == alert_id).first()
    if alert:
        alert.playbook_triggered = playbook
        alert.playbook_result    = result
        session.commit()


def run_runner():
    create_tables_sync()
    r      = redis.from_url(REDIS_URL)
    engine = create_engine(DATABASE_URL, pool_size=5)
    pubsub = r.pubsub()
    pubsub.subscribe(ALERTS_CHANNEL)

    logger.info("🤖 Playbook runner ready — listening for alerts...")

    for message in pubsub.listen():
        if message["type"] != "message":
            continue
        try:
            payload  = json.loads(message["data"])
            playbook = payload.get("playbook")
            alert_id = payload.get("alert_id")

            if not playbook:
                continue

            logger.info(
                f"📋 Alert #{alert_id} triggered playbook '{playbook}' "
                f"[{payload.get('severity','?').upper()}] — {payload.get('source_ip','?')}"
            )

            result = run_playbook(playbook, payload)

            with Session(engine) as session:
                save_playbook_result(session, alert_id, playbook, result)

        except json.JSONDecodeError:
            logger.warning("Received invalid JSON on alerts channel")
        except Exception as e:
            logger.exception(f"Runner error: {e}")
            time.sleep(1)


if __name__ == "__main__":
    run_runner()
