"""Файлы, пойманные на ловушках: список с хэшами и скачивание содержимого (только операторам)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import auth
from ..db import get_db
from ..models import Artifact, Trap, User

router = APIRouter(prefix="/api/artifacts", tags=["artifacts"])


def view(a: Artifact, trap_name: str = "") -> dict:
    return {"sha256": a.sha256, "size": a.size, "name": a.name, "kind": a.kind, "trap": trap_name, "src_ip": a.src_ip,
            "url": a.url, "seen_count": a.seen_count, "first_seen": a.first_seen.isoformat() + "Z",
            "last_seen": a.last_seen.isoformat() + "Z", "has_content": a.content is not None}


@router.get("")
def list_artifacts(limit: int = Query(100, ge=1, le=500), _: User = Depends(auth.current_user),
                   db: Session = Depends(get_db)):
    rows = db.execute(select(Artifact, Trap.name).outerjoin(Trap, Trap.id == Artifact.first_trap_id)
                      .order_by(Artifact.last_seen.desc()).limit(limit)).all()
    return {"items": [view(a, name or "") for a, name in rows]}


@router.get("/{sha256}/download")
def download(sha256: str, user: User = Depends(auth.require_role("admin", "operator")), db: Session = Depends(get_db)):
    a = db.get(Artifact, sha256.lower())
    if a is None or a.content is None:
        raise HTTPException(404, "Содержимое файла не сохранено")
    # вредоносный файл отдаётся только как вложение, никогда не как страница
    return Response(a.content, media_type="application/octet-stream",
                    headers={"Content-Disposition": f'attachment; filename="{a.sha256[:16]}.bin"',
                             "X-Content-Type-Options": "nosniff"})
