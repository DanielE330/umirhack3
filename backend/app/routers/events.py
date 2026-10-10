"""Просмотр событий: лента с фильтрами, статистика, экспорт IoC, поток в реальном времени."""
from __future__ import annotations

import asyncio
import csv
import io
import ipaddress
import uuid
from datetime import datetime, timedelta
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, PlainTextResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload

from .. import auth
from ..db import get_db
from ..models import Event, Trap, User, utcnow
from ..services import event_view, trap_status

router = APIRouter(prefix="/api", tags=["events"])

EVENT_TYPES = {"connect", "auth_attempt", "command", "http_request", "payload", "honeytoken", "session_end", "alert"}


def _filtered(stmt, trap_id, type_, src_ip, since, until, q):
    if trap_id:
        stmt = stmt.where(Event.trap_id == trap_id)
    if type_:
        stmt = stmt.where(Event.type == type_)
    if src_ip:
        stmt = stmt.where(Event.src_ip == src_ip)
    if since:
        stmt = stmt.where(Event.ts >= since)
    if until:
        stmt = stmt.where(Event.ts <= until)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(Event.username.ilike(like) | Event.command.ilike(like) | Event.password.ilike(like))
    return stmt


def _validate_type(type_: str | None) -> None:
    if type_ and type_ not in EVENT_TYPES:
        raise HTTPException(422, "Неизвестный тип события")


@router.get("/events")
def list_events(trap_id: int | None = None, type: str | None = None, src_ip: str | None = None,
                since: datetime | None = None, until: datetime | None = None, q: str | None = Query(None, max_length=100),
                before_id: int | None = None, limit: int = Query(50, ge=1, le=200),
                _: User = Depends(auth.current_user), db: Session = Depends(get_db)):
    _validate_type(type)
    stmt = _filtered(select(Event).options(joinedload(Event.trap)), trap_id, type, src_ip, since, until, q)
    if before_id:
        stmt = stmt.where(Event.id < before_id)
    rows = db.scalars(stmt.order_by(Event.id.desc()).limit(limit + 1)).all()
    page = rows[:limit]
    return {"items": [event_view(e) for e in page], "next_before_id": page[-1].id if len(rows) > limit else None}


def _csv_cell(value) -> str:
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text  # защита от CSV-инъекций в Excel


@router.get("/events/export.csv")
def export_events(trap_id: int | None = None, type: str | None = None, src_ip: str | None = None,
                  since: datetime | None = None, until: datetime | None = None, q: str | None = Query(None, max_length=100),
                  _: User = Depends(auth.current_user), db: Session = Depends(get_db)):
    _validate_type(type)
    stmt = _filtered(select(Event).options(joinedload(Event.trap)), trap_id, type, src_ip, since, until, q)
    rows = db.scalars(stmt.order_by(Event.id.desc()).limit(10000)).all()
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["id", "ts", "trap", "type", "src_ip", "src_port", "dst_port", "proto", "username", "password", "command"])
    for e in rows:
        w.writerow([_csv_cell(x) for x in (e.id, e.ts.isoformat() + "Z", e.trap.name, e.type, e.src_ip, e.src_port,
                                           e.dst_port, e.proto, e.username, e.password, e.command)])
    return PlainTextResponse(out.getvalue(), media_type="text/csv; charset=utf-8",
                             headers={"Content-Disposition": 'attachment; filename="events.csv"'})


def _ioc_rows(db: Session):
    return db.execute(
        select(Event.src_ip, func.count(), func.min(Event.ts), func.max(Event.ts))
        .where(Event.src_ip != "", Event.type != "alert").group_by(Event.src_ip).order_by(func.count().desc())).all()


@router.get("/iocs.csv")
def iocs_csv(_: User = Depends(auth.current_user), db: Session = Depends(get_db)):
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["ip", "events", "first_seen", "last_seen"])
    for ip, n, first, last in _ioc_rows(db):
        w.writerow([_csv_cell(ip), n, first.isoformat() + "Z", last.isoformat() + "Z"])
    return PlainTextResponse(out.getvalue(), media_type="text/csv; charset=utf-8",
                             headers={"Content-Disposition": 'attachment; filename="iocs.csv"'})


@router.get("/iocs.stix.json")
def iocs_stix(_: User = Depends(auth.current_user), db: Session = Depends(get_db)):
    """STIX 2.1: по индикатору на каждый наблюдаемый IP источника атак."""
    objects = []
    for ip, n, first, last in _ioc_rows(db):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        kind = "ipv4-addr" if addr.version == 4 else "ipv6-addr"
        stamp = first.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        objects.append({"type": "indicator", "spec_version": "2.1",
                        "id": f"indicator--{uuid.uuid5(uuid.NAMESPACE_URL, 'honeyforge:' + ip)}",
                        "created": stamp, "modified": last.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                        "name": f"Источник атаки на ловушки {ip}", "description": f"Событий: {n}",
                        "pattern": f"[{kind}:value = '{ip}']", "pattern_type": "stix", "valid_from": stamp,
                        "indicator_types": ["malicious-activity"]})
    bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}
    return JSONResponse(bundle, media_type="application/stix+json;version=2.1")


@router.get("/stats")
def stats(request: Request, _: User = Depends(auth.current_user), db: Session = Depends(get_db)):
    settings = auth.settings_of(request)
    now = utcnow()
    day = now - timedelta(hours=24)
    by_type = dict(db.execute(select(Event.type, func.count()).where(Event.ts >= day).group_by(Event.type)).all())

    def top(col, *extra):
        stmt = select(col, func.count().label("n")).where(Event.ts >= day, col != "", *extra) \
            .group_by(col).order_by(func.count().desc()).limit(10)
        return [{"value": v, "count": n} for v, n in db.execute(stmt).all()]

    hour = now - timedelta(minutes=60)
    buckets = {(hour + timedelta(minutes=i)).strftime("%H:%M"): 0 for i in range(1, 61)}
    for (ts,) in db.execute(select(Event.ts).where(Event.ts >= hour, Event.type != "alert")):
        key = ts.strftime("%H:%M")
        if key in buckets:
            buckets[key] += 1
    traps = db.scalars(select(Trap).options(joinedload(Trap.profile))).all()
    online = sum(1 for t in traps if trap_status(t, settings) == "online")
    return {"total_24h": sum(by_type.values()), "by_type": by_type, "top_sources": top(Event.src_ip, Event.type != "alert"),
            "top_usernames": top(Event.username, Event.type == "auth_attempt"),
            "top_passwords": top(Event.password, Event.type == "auth_attempt"),
            "timeline": [{"t": k, "n": v} for k, v in buckets.items()],
            "traps": {"total": len(traps), "online": online}}


@router.websocket("/ws/events")
async def ws_events(ws: WebSocket):
    """Поток новых событий. Защита от межсайтового перехвата: Origin должен совпасть с Host, сессия — полная."""
    settings = ws.app.state.settings
    origin = ws.headers.get("origin")
    if origin and urlparse(origin).netloc != ws.headers.get("host"):
        await ws.close(code=1008)
        return
    factory = ws.app.state.session_factory
    token = ws.cookies.get(auth.cookie_name(settings, "session"))

    def check() -> bool:
        with factory() as db:
            return auth.load_session_token(db, settings, token, "full") is not None

    if not await run_in_threadpool(check):
        await ws.close(code=1008)
        return
    await ws.accept()
    hub = ws.app.state.hub
    queue = hub.subscribe()
    try:
        while True:
            try:
                payload = await asyncio.wait_for(queue.get(), timeout=25)
            except asyncio.TimeoutError:
                if not await run_in_threadpool(check):  # сессию отозвали/она истекла
                    await ws.close(code=1008)
                    return
                await ws.send_json({"type": "ping"})
                continue
            await ws.send_json(payload)
    except WebSocketDisconnect:
        pass
    finally:
        hub.unsubscribe(queue)
