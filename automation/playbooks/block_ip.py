
import os
import logging
import subprocess
from datetime import datetime

from sqlalchemy.orm import Session
from sqlalchemy import create_engine

from database.models import BlockedIP, Alert
from automation.playbooks.notify_slack import execute as notify

logger = logging.getLogger(__name__)

DATABASE_URL       = os.getenv("DATABASE_URL", "postgresql://siem:siempass@localhost:5432/siemdb")
AUTO_UNBLOCK_MINS  = int(os.getenv("AUTO_UNBLOCK_MINUTES", "60"))   # 0 = never
DRY_RUN            = os.getenv("IPTABLES_DRY_RUN", "true").lower() == "true"


def _iptables_block(ip: str) -> tuple[bool, str]:
    if DRY_RUN:
        msg = f"[DRY RUN] Would block {ip} via iptables"
        logger.info(msg)
        return True, msg

    try:
        check = subprocess.run(
            ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True
        )
        if check.returncode == 0:
            return True, f"{ip} already blocked"

        subprocess.run(
            ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
            check=True, capture_output=True
        )
        return True, f"iptables DROP rule added for {ip}"
    except FileNotFoundError:
        return False, "iptables not found — run container with --cap-add NET_ADMIN"
    except subprocess.CalledProcessError as e:
        return False, f"iptables error: {e.stderr.decode()}"


def _iptables_unblock(ip: str) -> tuple[bool, str]:
    if DRY_RUN:
        return True, f"[DRY RUN] Would unblock {ip}"
    try:
        subprocess.run(
            ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            check=True, capture_output=True
        )
        return True, f"iptables rule removed for {ip}"
    except subprocess.CalledProcessError as e:
        return False, f"iptables error: {e.stderr.decode()}"


def _store_blocked_ip(ip: str, reason: str, alert_id: int):
    engine  = create_engine(DATABASE_URL)
    with Session(engine) as session:
        existing = session.query(BlockedIP).filter(BlockedIP.ip_address == ip).first()
        if existing:
            existing.is_active        = True
            existing.blocked_at       = datetime.utcnow()
            existing.reason           = reason
            existing.alert_id         = alert_id
            existing.auto_unblock_after = AUTO_UNBLOCK_MINS or None
        else:
            record = BlockedIP(
                ip_address        = ip,
                reason            = reason,
                alert_id          = alert_id,
                auto_unblock_after= AUTO_UNBLOCK_MINS or None,
            )
            session.add(record)
        session.commit()


def execute(alert_payload: dict) -> dict:

    source_ip = alert_payload.get("source_ip")
    alert_id  = alert_payload.get("alert_id", 0)
    rule_name = alert_payload.get("rule_name", "Unknown Rule")
    severity  = alert_payload.get("severity", "high")

    if not source_ip:
        return {"status": "skipped", "message": "No source_ip in alert payload"}


    success, iptables_msg = _iptables_block(source_ip)

    reason = f"Auto-blocked by rule: {rule_name}"
    _store_blocked_ip(source_ip, reason, alert_id)

    notify_result = notify(alert_payload, extra_message=f"\n🔒 *Action Taken:* {iptables_msg}")

    return {
        "status":        "success" if success else "partial",
        "ip_blocked":    source_ip,
        "iptables":      iptables_msg,
        "db_stored":     True,
        "notification":  notify_result.get("status"),
        "auto_unblock":  f"{AUTO_UNBLOCK_MINS}m" if AUTO_UNBLOCK_MINS else "never",
    }
