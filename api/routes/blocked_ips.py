
import subprocess
import logging
import os
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from database.connection import get_db
from database.models import BlockedIP
from api.schemas import BlockedIPOut, BlockedIPCreate

logger    = logging.getLogger(__name__)
router    = APIRouter()
DRY_RUN   = os.getenv("IPTABLES_DRY_RUN", "true").lower() == "true"



@router.get("", response_model=list[BlockedIPOut])
async def list_blocked_ips(
    active_only: bool          = True,
    db:          AsyncSession  = Depends(get_db),
):
    query = select(BlockedIP).order_by(desc(BlockedIP.blocked_at))
    if active_only:
        query = query.where(BlockedIP.is_active == True)
    result = await db.execute(query)
    return result.scalars().all()



@router.post("", response_model=BlockedIPOut, status_code=201)
async def block_ip(body: BlockedIPCreate, db: AsyncSession = Depends(get_db)):
    # Check if already blocked
    existing_q = await db.execute(
        select(BlockedIP).where(BlockedIP.ip_address == body.ip_address)
    )
    existing = existing_q.scalar_one_or_none()
    if existing and existing.is_active:
        raise HTTPException(status_code=409, detail=f"{body.ip_address} is already blocked")

    # Apply iptables rule
    iptables_msg = _apply_block(body.ip_address)
    logger.info(f"Manual block: {body.ip_address} — {iptables_msg}")

    if existing:
        existing.is_active          = True
        existing.blocked_at         = datetime.utcnow()
        existing.reason             = body.reason
        existing.unblocked_at       = None
        existing.auto_unblock_after = body.auto_unblock_after
        await db.commit()
        await db.refresh(existing)
        return existing

    record = BlockedIP(
        ip_address          = body.ip_address,
        reason              = body.reason,
        auto_unblock_after  = body.auto_unblock_after,
    )
    db.add(record)
    await db.commit()
    await db.refresh(record)
    return record



@router.delete("/{ip_address}", status_code=200)
async def unblock_ip(ip_address: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(BlockedIP).where(
            BlockedIP.ip_address == ip_address,
            BlockedIP.is_active  == True,
        )
    )
    record = result.scalar_one_or_none()
    if not record:
        raise HTTPException(status_code=404, detail=f"{ip_address} is not currently blocked")

    iptables_msg = _apply_unblock(ip_address)
    logger.info(f"Unblocked: {ip_address} — {iptables_msg}")

    record.is_active    = False
    record.unblocked_at = datetime.utcnow()
    await db.commit()

    return {"status": "unblocked", "ip": ip_address, "iptables": iptables_msg}



def _apply_block(ip: str) -> str:
    if DRY_RUN:
        return f"[DRY RUN] Would add iptables DROP rule for {ip}"
    try:
        subprocess.run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"], check=True, capture_output=True)
        return f"iptables DROP rule added for {ip}"
    except Exception as e:
        return f"iptables error: {e}"


def _apply_unblock(ip: str) -> str:
    if DRY_RUN:
        return f"[DRY RUN] Would remove iptables DROP rule for {ip}"
    try:
        subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True, capture_output=True)
        return f"iptables DROP rule removed for {ip}"
    except Exception as e:
        return f"iptables error: {e}"
