"""Канал агент ↔ центр. Пути выглядят как раздача статики/логов обычного сайта (MASK-2), а не как `/api/honeypot`.
Аутентификация: Bearer-токен ловушки (в БД только его хэш)."""
from __future__ import annotations

import hashlib
import json
import uuid

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import auth
from .. import geo, scoring
from ..channel_crypto import decrypt_payload, derive_payload_key, encrypt_payload
from ..db import get_db
from ..models import Event, Trap, utcnow
from ..schemas import AgentBatch
from ..services import hash_agent_token, ingest_events, profile_config

router = APIRouter(prefix="/assets/v1", include_in_schema=False)


def agent_trap(request: Request, db: Session = Depends(get_db)) -> Trap:
    header = request.headers.get("authorization", "")
    token = header[7:] if header.lower().startswith("bearer ") else ""
    trap = db.scalar(select(Trap).where(Trap.token_hash == hash_agent_token(token))) if token else None
    if trap is None:
        raise HTTPException(404, "Not Found")  # не раскрываем, что здесь что-то есть
    request.state.raw_token = token
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
    manifest_data = {"rev": digest, "state": state, "poll": poll, "config": config, "cmds": commands}

    raw_token = getattr(request.state, "raw_token", "")
    if raw_token and ("enc" in request.headers.get("accept-encoding-custom", "") or v.startswith("2")):
        key = derive_payload_key(raw_token)
        return encrypt_payload(manifest_data, key)
    return manifest_data


@router.api_route("/telemetry/sync", methods=["GET", "POST"])
async def canary_sync(request: Request, token: str = "", background: BackgroundTasks = BackgroundTasks(), db: Session = Depends(get_db)):
    """Внеполосный перехват канареечного токена (OOB Canary Trigger).
    
    Когда атакующий использует украденный из ловушки токен во внешней сети,
    запрос попадает сюда. Мы связываем его с исходной сессией и фиксируем подтвержденную эксфильтрацию.
    """
    settings = auth.settings_of(request)
    client_ip = auth.client_ip(request)
    user_agent = request.headers.get("user-agent", "")
    token_str = (token or request.query_params.get("token") or "").strip()

    if not token_str:
        return {"status": "ok", "synced": True}

    all_ht = db.scalars(select(Event).where(Event.type == "honeytoken").order_by(Event.id.desc()).limit(200)).all()
    matched = None
    for ev in all_ht:
        if ev.data and ev.data.get("token_id") == token_str:
            matched = ev
            break

    now = utcnow()
    delay = 0.0
    sess_id = matched.session_id if matched else "unknown"
    trap_id = matched.trap_id if matched else None
    planted_ip = matched.src_ip if matched else "unknown"
    if matched and matched.ts:
        delay = max(0.0, (now - matched.ts).total_seconds())

    fallback_trap_id = db.scalar(select(Trap.id).limit(1)) or 1
    effective_trap_id = trap_id or fallback_trap_id

    oob_event = Event(
        uid=f"oob-{token_str[:16]}-{uuid.uuid4().hex[:12]}",
        trap_id=effective_trap_id,
        ts=now,
        session_id=sess_id,
        type="honeytoken",
        src_ip=client_ip,
        command=f"OOB Canary Tripped: {token_str}",
        data={
            "action": "exfiltrated",
            "token_id": token_str,
            "planted_session_id": sess_id,
            "planted_ip": planted_ip,
            "delay_seconds": round(delay, 1),
            "user_agent": user_agent[:250],
        },
        threat_score=100,
        category="credential_access",
        needs_review=False,
    )
    db.add(oob_event)
    db.commit()
    db.refresh(oob_event)

    trap_name = db.get(Trap, effective_trap_id).name if db.get(Trap, effective_trap_id) else "canary"
    view = {
        "id": oob_event.id,
        "trap_id": trap_id,
        "trap": trap_name,
        "session_id": sess_id,
        "type": "honeytoken",
        "src_ip": client_ip,
        "command": oob_event.command,
        "username": None,
        "data": oob_event.data,
        "threat_score": 100,
        "category": "credential_access",
        "ts": oob_event.ts.isoformat() + "Z",
    }

    hub = getattr(request.app.state, "hub", None)
    if hub:
        hub.publish(view)

    orchestrator = getattr(request.app.state, "orchestrator", None)
    if orchestrator:
        background.add_task(_notify, orchestrator, view)

    honeymind = getattr(request.app.state, "honeymind", None)
    if honeymind:
        scoring.submit_score_event(request.app.state.session_factory, honeymind, orchestrator, view)

    return {"status": "error", "code": "AUTH_EXPIRED", "message": "Token expired or revoked"}


NOTIFY_TYPES = {"alert", "honeytoken"}  # о чём сообщать оператору в Telegram


def _notify(orchestrator, view: dict) -> None:
    try:
        orchestrator.request("POST", "/", {"event_name": view["type"], "attacker_ip": view["src_ip"],
                                           "properties": {"trap": view["trap"], "detail": view["command"] or view["username"]}},
                             timeout=20, base="/api/v1/notify")
    except Exception as exc:
        print(f"⚠️ [Center Notify] Ошибка отправки алерта в оркестратор: {exc}", flush=True)


@router.post("/log")
async def collect(request: Request, background: BackgroundTasks, trap: Trap = Depends(agent_trap)):
    settings = auth.settings_of(request)
    raw = await request.body()
    if len(raw) > settings.max_body_bytes:
        raise HTTPException(413, "Payload Too Large")
    try:
        data = json.loads(raw)
        if isinstance(data, dict) and "enc" in data and "nonce" in data:
            raw_token = getattr(request.state, "raw_token", "")
            if not raw_token:
                raise ValueError("Отсутствует токен ловушки для дешифрования")
            key = derive_payload_key(raw_token)
            data = decrypt_payload(data, key)
            batch = AgentBatch.model_validate(data)
        else:
            batch = AgentBatch.model_validate(data)
    except Exception as exc:
        print(f"⚠️ [Agent API] Ошибка парсинга/дешифрования батча: {exc}", flush=True)
        raise HTTPException(422, "Unprocessable Entity")
    factory = request.app.state.session_factory

    def work():
        with factory() as db:
            tr = db.get(Trap, trap.id)
            tr.last_seen = utcnow()
            return ingest_events(db, settings, tr, batch.events)

    views, dup = await run_in_threadpool(work)
    if settings.geoip_url and views:
        background.add_task(geo.enrich, factory, settings.geoip_url, {v["src_ip"] for v in views if v["src_ip"]})
    hub = request.app.state.hub
    honeymind, orchestrator = request.app.state.honeymind, request.app.state.orchestrator
    for view in views:
        hub.publish(view)
        if view["type"] in NOTIFY_TYPES:
            background.add_task(_notify, orchestrator, view)
        # Оценка HoneyMind — в ограниченном пуле потоков (app/scoring.py), уже после db.commit()
        # внутри work(); не блокирует ответ агенту, падение HoneyMind не роняет приём событий.
        scoring.submit_score_event(request.app.state.session_factory, honeymind, orchestrator, view)
        if view["type"] == "session_end":
            scoring.submit_session_assessment(request.app.state.session_factory, honeymind, view["session_id"], orchestrator)
    return {"ok": len(batch.events) - dup, "dup": dup}
