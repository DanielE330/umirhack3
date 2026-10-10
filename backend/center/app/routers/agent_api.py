"""Канал агент ↔ центр. Пути выглядят как раздача статики/логов обычного сайта (MASK-2), а не как `/api/honeypot`.
Аутентификация: Bearer-токен ловушки (в БД только его хэш)."""
from __future__ import annotations

import hashlib
import json

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import auth
from ..db import get_db
from ..models import Trap, utcnow
from ..schemas import AgentBatch
from ..services import hash_agent_token, ingest_events, profile_config

router = APIRouter(prefix="/assets/v1", include_in_schema=False)


def agent_trap(request: Request, db: Session = Depends(get_db)) -> Trap:
    header = request.headers.get("authorization", "")
    token = header[7:] if header.lower().startswith("bearer ") else ""
    trap = db.scalar(select(Trap).where(Trap.token_hash == hash_agent_token(token))) if token else None
    if trap is None:
        raise HTTPException(404, "Not Found")  # не раскрываем, что здесь что-то есть
    return trap


@router.get("/manifest.json")
def manifest(request: Request, v: str = "", trap: Trap = Depends(agent_trap), db: Session = Depends(get_db)):
    """Конфигурация по профилю + команды; заодно это и heartbeat."""
    settings = auth.settings_of(request)
    trap.last_seen = utcnow()
    trap.host = auth.client_ip(request)
    trap.agent_version = v[:32]
    commands = [trap.pending_command] if trap.pending_command else []
    trap.pending_command = None
    config = profile_config(trap.profile) if trap.profile else None
    state = "run" if (trap.enabled and config) else "stop"
    digest = hashlib.sha256(json.dumps([state, config], sort_keys=True).encode()).hexdigest()[:16]
    db.commit()
    poll = (config or {}).get("masking", {}).get("beacon_interval", settings.default_beacon_seconds)
    return {"rev": digest, "state": state, "poll": poll, "config": config, "cmds": commands}


NOTIFY_TYPES = {"alert", "honeytoken"}  # о чём сообщать оператору в Telegram


def _notify(orchestrator, view: dict) -> None:
    try:
        orchestrator.request("POST", "/", {"event_name": view["type"], "attacker_ip": view["src_ip"],
                                           "properties": {"trap": view["trap"], "detail": view["command"] or view["username"]}},
                             timeout=20, base="/api/v1/notify")
    except HTTPException:
        pass  # уведомление вторично: событие уже сохранено и показано в ленте


@router.post("/log")
async def collect(request: Request, background: BackgroundTasks, trap: Trap = Depends(agent_trap)):
    settings = auth.settings_of(request)
    raw = await request.body()
    if len(raw) > settings.max_body_bytes:
        raise HTTPException(413, "Payload Too Large")
    try:
        batch = AgentBatch.model_validate_json(raw)
    except Exception:
        raise HTTPException(422, "Unprocessable Entity")
    factory = request.app.state.session_factory

    def work():
        with factory() as db:
            tr = db.get(Trap, trap.id)
            tr.last_seen = utcnow()
            return ingest_events(db, settings, tr, batch.events)

    views, dup = await run_in_threadpool(work)
    hub = request.app.state.hub
    for view in views:
        hub.publish(view)
        if view["type"] in NOTIFY_TYPES:
            background.add_task(_notify, request.app.state.orchestrator, view)
    return {"ok": len(batch.events) - dup, "dup": dup}
