"""Журнал аудита действий операторов (только администратор)."""
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import auth
from ..db import get_db
from ..models import AuditLog, User

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("")
def list_audit(actor: str | None = Query(None, max_length=64), action: str | None = Query(None, max_length=64),
               since: datetime | None = None, before_id: int | None = None, limit: int = Query(100, ge=1, le=500),
               _: User = Depends(auth.require_perm("audit.view")), db: Session = Depends(get_db)):
    stmt = select(AuditLog)
    if actor:
        stmt = stmt.where(AuditLog.actor == actor)
    if action:
        stmt = stmt.where(AuditLog.action.like(action + "%"))
    if since:
        stmt = stmt.where(AuditLog.ts >= since)
    if before_id:
        stmt = stmt.where(AuditLog.id < before_id)
    rows = db.scalars(stmt.order_by(AuditLog.id.desc()).limit(limit + 1)).all()
    page = rows[:limit]
    return {"items": [{"id": r.id, "ts": r.ts.isoformat() + "Z", "actor": r.actor, "action": r.action,
                       "detail": r.detail, "ip": r.ip} for r in page],
            "next_before_id": page[-1].id if len(rows) > limit else None}
