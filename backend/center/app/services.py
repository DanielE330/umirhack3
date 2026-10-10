"""Приём телеметрии: дедупликация, запись, алерты, сериализация."""
from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .config import Settings
from .models import Event, Profile, Trap, utcnow
from .schemas import AgentEvent

STATUS_NEVER, STATUS_ONLINE, STATUS_OFFLINE = "never", "online", "offline"


def hash_agent_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def new_agent_token() -> str:
    return "hf_" + uuid.uuid4().hex + uuid.uuid4().hex  # 244 бита энтропии


def trap_status(trap: Trap, settings: Settings) -> str:
    if trap.last_seen is None:
        return STATUS_NEVER
    interval = (trap.profile.masking or {}).get("beacon_interval", settings.default_beacon_seconds) if trap.profile \
        else settings.default_beacon_seconds
    grace = max(interval * 3, 30)  # джиттер и сетевые задержки: офлайн после трёх пропущенных маяков
    return STATUS_ONLINE if utcnow() - trap.last_seen <= timedelta(seconds=grace) else STATUS_OFFLINE


def profile_config(profile: Profile) -> dict:
    return {"level": profile.level, "services": profile.services, "decoys": profile.decoys,
            "logging": profile.logging, "masking": profile.masking}


def event_view(e: Event) -> dict:
    return {"id": e.id, "uid": e.uid, "trap_id": e.trap_id, "trap": e.trap.name if e.trap else "",
            "ts": e.ts.isoformat() + "Z", "type": e.type, "src_ip": e.src_ip, "src_port": e.src_port,
            "dst_port": e.dst_port, "proto": e.proto, "session_id": e.session_id, "username": e.username,
            "password": e.password, "command": e.command, "data": e.data}


def _to_naive_utc(ts: float) -> datetime:
    now = utcnow()
    dt = datetime.fromtimestamp(ts, tz=timezone.utc).replace(tzinfo=None)
    return min(dt, now + timedelta(minutes=5))  # часы ловушки могут уходить вперёд, но не бесконечно


def ingest_events(db: Session, settings: Settings, trap: Trap, items: list[AgentEvent],
                  ) -> tuple[list[dict], int]:
    """Сохраняет новые события, возвращает (представления новых событий, число дубликатов)."""
    uids = [i.uid for i in items]
    known = set(db.scalars(select(Event.uid).where(Event.uid.in_(uids)))) if uids else set()
    created: list[Event] = []
    seen_in_batch: set[str] = set()
    for item in items:
        if item.uid in known or item.uid in seen_in_batch:
            continue
        seen_in_batch.add(item.uid)
        ev = Event(uid=item.uid, trap_id=trap.id, ts=_to_naive_utc(item.ts), type=item.type, src_ip=item.src_ip,
                   src_port=item.src_port, dst_port=item.dst_port, proto=item.proto, session_id=item.session_id,
                   username=item.username, password=item.password, command=item.command, data=item.data)
        db.add(ev)
        created.append(ev)
    db.flush()

    alerts = _make_alerts(db, settings, trap, created)
    db.commit()
    views = [event_view(e) for e in created + alerts]
    return views, len(items) - len(created)


def _make_alerts(db: Session, settings: Settings, trap: Trap, created: list[Event]) -> list[Event]:
    """≥N попыток входа с одного IP за окно -> одно событие `alert` на окно (FR-C7)."""
    alerts: list[Event] = []
    window = timedelta(seconds=settings.alert_window_seconds)
    for ip in {e.src_ip for e in created if e.type == "auth_attempt" and e.src_ip}:
        since = utcnow() - window
        attempts = db.scalar(select(func.count()).select_from(Event).where(
            Event.trap_id == trap.id, Event.type == "auth_attempt", Event.src_ip == ip, Event.received_at >= since)) or 0
        if attempts < settings.alert_threshold:
            continue
        already = db.scalar(select(func.count()).select_from(Event).where(
            Event.trap_id == trap.id, Event.type == "alert", Event.src_ip == ip, Event.received_at >= since)) or 0
        if already:
            continue
        alert = Event(uid="alert-" + uuid.uuid4().hex, trap_id=trap.id, ts=utcnow(), type="alert", src_ip=ip,
                      proto="center", command=f"{attempts} попыток входа за {settings.alert_window_seconds} с",
                      data={"rule": "bruteforce", "attempts": attempts})
        db.add(alert)
        alerts.append(alert)
    db.flush()
    return alerts
