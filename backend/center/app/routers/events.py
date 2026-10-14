"""Просмотр событий: лента с фильтрами, статистика, экспорт IoC, поток в реальном времени."""
from __future__ import annotations

import asyncio
import csv
import io
import ipaddress
import uuid
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, PlainTextResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload

from pydantic import BaseModel, Field

from .. import auth, geo
from ..db import get_db
from ..models import Artifact, Event, EventLabel, IpInfo, SessionAssessment, Trap, User, utcnow
from ..services import event_view, trap_status

router = APIRouter(prefix="/api", tags=["events"])

EVENT_TYPES = {"connect", "auth_attempt", "command", "http_request", "payload", "honeytoken", "session_end", "alert"}


def _filtered(stmt, trap_id, type_, src_ip, since, until, q, session_id=None, min_score=None):
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
    if session_id:
        stmt = stmt.where(Event.session_id == session_id)
    if min_score is not None:
        stmt = stmt.where(Event.threat_score >= min_score)
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
                session_id: str | None = Query(None, max_length=64), min_score: int | None = Query(None, ge=0, le=100),
                before_id: int | None = None, limit: int = Query(50, ge=1, le=200),
                _: User = Depends(auth.require_perm("events.view")), db: Session = Depends(get_db)):
    _validate_type(type)
    stmt = _filtered(select(Event).options(joinedload(Event.trap)), trap_id, type, src_ip, since, until, q, session_id, min_score)
    if before_id:
        stmt = stmt.where(Event.id < before_id)
    rows = db.scalars(stmt.order_by(Event.id.desc()).limit(limit + 1)).all()
    page = rows[:limit]
    geo_map = geo.cached(db, {e.src_ip for e in page})
    return {"items": [event_view(e, geo_map) for e in page], "next_before_id": page[-1].id if len(rows) > limit else None}


@router.get("/sessions/{session_id}")
def get_session_assessment(session_id: str, _: User = Depends(auth.require_perm("events.view")), db: Session = Depends(get_db)):
    """Итог сессии: длительность и счётчики по событиям + оценка HoneyMind «человек или бот» (считается при session_end)."""
    first, last, total, src = db.execute(select(func.min(Event.ts), func.max(Event.ts), func.count(), func.min(Event.src_ip))
                                         .where(Event.session_id == session_id)).one()
    a = db.get(SessionAssessment, session_id)
    if not total and a is None:
        raise HTTPException(404, "Сессия ещё не оценена")
    counts = dict(db.execute(select(Event.type, func.count()).where(Event.session_id == session_id).group_by(Event.type)).all())
    cmds = db.scalars(select(Event.command).where(Event.session_id == session_id, Event.command != "").order_by(Event.id.asc()).limit(50)).all()
    summary = {"events": total, "src_ip": src or "", "first_ts": first.isoformat() + "Z" if first else None,
               "last_ts": last.isoformat() + "Z" if last else None,
               "duration_seconds": round((last - first).total_seconds(), 1) if first and last else 0,
               "commands": counts.get("command", 0), "auth_attempts": counts.get("auth_attempt", 0),
               "honeytokens": counts.get("honeytoken", 0),
               "commands_list": [c for c in cmds if c]}
    out = {"session_id": session_id, "is_human": None, "human_probability": None, "human_method": None,
           "human_reason": None, "script_seen_before": None, "threat_score": None,
           "download_then_execute": None, "ssh_client": None, "updated_at": None, "summary": summary}
    if a is not None:
        res_data = a.result or {}
        out.update(is_human=a.is_human, human_probability=a.human_probability, human_method=a.human_method,
                   human_reason=a.human_reason, script_seen_before=a.script_seen_before,
                   threat_score=a.threat_score, download_then_execute=a.download_then_execute,
                   ssh_client=a.ssh_client,
                   dual_loop_report=res_data.get("dual_loop_report"),
                   detection_rules=res_data.get("detection_rules"),
                   mitre_engage=res_data.get("mitre_engage"),
                   intent_prediction=res_data.get("intent_prediction"),
                   hassh_profile=res_data.get("hassh_profile"),
                   updated_at=a.updated_at.isoformat() + "Z")
    return out


def _get_or_synth_session_artifacts(db: Session, session_id: str, request: Request) -> tuple[dict[str, Any], dict[str, Any]]:
    from ..scoring import _event_payload
    a = db.get(SessionAssessment, session_id)
    res_data = (a.result or {}) if a and a.result else {}
    rules = res_data.get("detection_rules")
    reports = res_data.get("dual_loop_report")
    if rules and reports:
        return rules, reports

    honeymind = getattr(request.app.state, "honeymind", None)
    if honeymind:
        rows = db.scalars(select(Event).where(Event.session_id == session_id).order_by(Event.ts)).all()
        events = [_event_payload({
            "type": r.type, "command": r.command, "username": r.username, "password": r.password,
            "session_id": r.session_id, "ts": r.ts.isoformat() + "Z" if r.ts else "", "data": r.data,
        }) for r in rows]
        if events:
            if not rules:
                rules = honeymind.export_detection_rules(events, session_id=session_id) or {}
            if not reports:
                reports = honeymind.generate_report(events=events) or {}
            if a and rules and reports:
                if not a.result or not isinstance(a.result, dict):
                    a.result = {}
                a.result["detection_rules"] = rules
                a.result["dual_loop_report"] = reports
                db.commit()
    return rules or {}, reports or {}


@router.get("/sessions/{session_id}/sigma.yml")
def download_session_sigma(session_id: str, request: Request, _: User = Depends(auth.require_perm("events.export")), db: Session = Depends(get_db)):
    rules, _ = _get_or_synth_session_artifacts(db, session_id, request)
    sigma = rules.get("sigma_yaml")
    if not sigma:
        raise HTTPException(404, "Правило Sigma не сформировано для этой сессии")
    return PlainTextResponse(sigma, media_type="application/x-yaml; charset=utf-8",
                             headers={"Content-Disposition": f'attachment; filename="sigma_{session_id[:16]}.yml"'})


@router.get("/sessions/{session_id}/yara.yar")
def download_session_yara(session_id: str, request: Request, _: User = Depends(auth.require_perm("events.export")), db: Session = Depends(get_db)):
    rules, _ = _get_or_synth_session_artifacts(db, session_id, request)
    yara = rules.get("yara_rule")
    if not yara:
        raise HTTPException(404, "Правило YARA не сформировано для этой сессии")
    return PlainTextResponse(yara, media_type="text/plain; charset=utf-8",
                             headers={"Content-Disposition": f'attachment; filename="rule_{session_id[:16]}.yar"'})


@router.get("/sessions/{session_id}/report.md")
def download_session_report(session_id: str, request: Request, _: User = Depends(auth.require_perm("events.view")), db: Session = Depends(get_db)):
    _, reports = _get_or_synth_session_artifacts(db, session_id, request)
    brief = (reports or {}).get("executive_markdown") or (reports or {}).get("executive_brief_markdown")
    if not brief:
        raise HTTPException(404, "Executive Brief не сформирован для этой сессии")
    return PlainTextResponse(brief, media_type="text/markdown; charset=utf-8",
                             headers={"Content-Disposition": f'attachment; filename="executive_brief_{session_id[:16]}.md"'})


@router.get("/sessions/{session_id}/dfir.md")
def download_session_dfir(session_id: str, request: Request, _: User = Depends(auth.require_perm("events.view")), db: Session = Depends(get_db)):
    _, reports = _get_or_synth_session_artifacts(db, session_id, request)
    dfir = (reports or {}).get("technical_markdown") or (reports or {}).get("technical_dfir_markdown")
    if not dfir:
        raise HTTPException(404, "DFIR-отчёт не сформирован для этой сессии")
    return PlainTextResponse(dfir, media_type="text/markdown; charset=utf-8",
                             headers={"Content-Disposition": f'attachment; filename="technical_dfir_{session_id[:16]}.md"'})


def _csv_cell(value) -> str:
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text  # защита от CSV-инъекций в Excel


@router.get("/events/export.csv")
def export_events(trap_id: int | None = None, type: str | None = None, src_ip: str | None = None,
                  since: datetime | None = None, until: datetime | None = None, q: str | None = Query(None, max_length=100),
                  session_id: str | None = Query(None, max_length=64), min_score: int | None = Query(None, ge=0, le=100),
                  _: User = Depends(auth.require_perm("events.export")), db: Session = Depends(get_db)):
    _validate_type(type)
    stmt = _filtered(select(Event).options(joinedload(Event.trap)), trap_id, type, src_ip, since, until, q, session_id, min_score)
    rows = db.scalars(stmt.order_by(Event.id.desc()).limit(10000)).all()
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["id", "ts", "trap", "type", "src_ip", "country", "asn", "src_port", "dst_port", "proto", "username",
                "password", "command"])
    geo_map = geo.cached(db, {e.src_ip for e in rows})
    for e in rows:
        g = geo_map.get(e.src_ip) or {}
        w.writerow([_csv_cell(x) for x in (e.id, e.ts.isoformat() + "Z", e.trap.name, e.type, e.src_ip,
                                           g.get("country_code", ""), g.get("asn", ""), e.src_port,
                                           e.dst_port, e.proto, e.username, e.password, e.command)])
    return PlainTextResponse(out.getvalue(), media_type="text/csv; charset=utf-8",
                             headers={"Content-Disposition": 'attachment; filename="events.csv"'})


def _ioc_rows(db: Session):
    return db.execute(
        select(Event.src_ip, func.count(), func.min(Event.ts), func.max(Event.ts))
        .where(Event.src_ip != "", Event.type != "alert").group_by(Event.src_ip).order_by(func.count().desc())).all()


@router.get("/iocs.csv")
def iocs_csv(_: User = Depends(auth.require_perm("iocs.export")), db: Session = Depends(get_db)):
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["ip", "country", "asn", "org", "events", "first_seen", "last_seen"])
    rows = _ioc_rows(db)
    geo_map = geo.cached(db, {r[0] for r in rows})
    for ip, n, first, last in rows:
        g = geo_map.get(ip) or {}
        w.writerow([_csv_cell(ip), g.get("country_code", ""), g.get("asn", ""), _csv_cell(g.get("org", "")), n,
                    first.isoformat() + "Z", last.isoformat() + "Z"])
    return PlainTextResponse(out.getvalue(), media_type="text/csv; charset=utf-8",
                             headers={"Content-Disposition": 'attachment; filename="iocs.csv"'})


@router.get("/iocs.stix.json")
def iocs_stix(_: User = Depends(auth.require_perm("iocs.export")), db: Session = Depends(get_db)):
    """STIX 2.1: по индикатору на каждый наблюдаемый IP источника атак и хэши пойманных файлов."""
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

    # Хэши вредоносных файлов (SHA-256)
    for art in db.scalars(select(Artifact).order_by(Artifact.last_seen.desc())).all():
        stamp = art.first_seen.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        objects.append({
            "type": "indicator", "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid5(uuid.NAMESPACE_URL, 'honeyforge:file:' + art.sha256)}",
            "created": stamp, "modified": art.last_seen.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "name": f"Вредоносный файл: {art.name or art.sha256[:16]}",
            "description": f"Размер: {art.size} байт, тип: {art.kind}, источник: {art.src_ip}",
            "pattern": f"[file:hashes.'SHA-256' = '{art.sha256}']",
            "pattern_type": "stix", "valid_from": stamp,
            "indicator_types": ["malicious-activity"],
        })
    bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}
    return JSONResponse(bundle, media_type="application/stix+json;version=2.1")


@router.get("/iocs-hashes.csv")
def iocs_hashes_csv(_: User = Depends(auth.require_perm("iocs.export")), db: Session = Depends(get_db)):
    """CSV-экспорт хэшей вредоносных файлов (SHA-256), пойманных на ловушках."""
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["sha256", "filename", "size_bytes", "kind", "src_ip", "seen_count", "first_seen", "last_seen"])
    for a in db.scalars(select(Artifact).order_by(Artifact.last_seen.desc())).all():
        w.writerow([
            _csv_cell(a.sha256), _csv_cell(a.name), a.size, _csv_cell(a.kind),
            _csv_cell(a.src_ip), a.seen_count, a.first_seen.isoformat() + "Z", a.last_seen.isoformat() + "Z",
        ])
    return PlainTextResponse(out.getvalue(), media_type="text/csv; charset=utf-8",
                             headers={"Content-Disposition": 'attachment; filename="iocs-hashes.csv"'})


@router.get("/stats")
def stats(request: Request, _: User = Depends(auth.require_perm("events.view")), db: Session = Depends(get_db)):
    settings = auth.settings_of(request)
    now = utcnow()
    day = now - timedelta(hours=24)
    by_type = dict(db.execute(select(Event.type, func.count()).where(Event.ts >= day).group_by(Event.type)).all())

    def top(col, *extra):
        stmt = select(col, func.count().label("n")).where(Event.ts >= day, col != "", *extra) \
            .group_by(col).order_by(func.count().desc()).limit(10)
        return [{"value": v, "count": n} for v, n in db.execute(stmt).all()]

    def top_geo(col):
        stmt = select(col, func.count().label("n")).select_from(Event).join(IpInfo, IpInfo.ip == Event.src_ip) \
            .where(Event.ts >= day, Event.type != "alert", col != "", IpInfo.country_code != "--") \
            .group_by(col).order_by(func.count().desc()).limit(10)
        return [{"value": v, "count": n} for v, n in db.execute(stmt).all()]

    hour = now - timedelta(minutes=60)
    buckets = {(hour + timedelta(minutes=i)).strftime("%H:%M"): 0 for i in range(1, 61)}
    for (ts,) in db.execute(select(Event.ts).where(Event.ts >= hour, Event.type != "alert")):
        key = ts.strftime("%H:%M")
        if key in buckets:
            buckets[key] += 1
    hours = {(now - timedelta(hours=23 - i)).strftime("%d.%m %H:00"): {"n": 0, "auth": 0, "alert": 0} for i in range(24)}
    for ts, typ in db.execute(select(Event.ts, Event.type).where(Event.ts >= now - timedelta(hours=24))):
        slot = hours.get(ts.strftime("%d.%m %H:00"))
        if slot is not None:
            slot["n"] += 1
            if typ in ("auth_attempt", "alert"):
                slot["auth" if typ == "auth_attempt" else "alert"] += 1
    traps = db.scalars(select(Trap).options(joinedload(Trap.profile))).all()
    online = sum(1 for t in traps if trap_status(t, settings) == "online")
    return {"total_24h": sum(by_type.values()), "by_type": by_type, "top_sources": top(Event.src_ip, Event.type != "alert"),
            "top_countries": top_geo(IpInfo.country), "top_asn": top_geo(IpInfo.asn),
            "top_usernames": top(Event.username, Event.type == "auth_attempt"),
            "top_passwords": top(Event.password, Event.type == "auth_attempt"),
            "timeline": [{"t": k, "n": v} for k, v in buckets.items()],
            "by_hour": [{"t": k, **v} for k, v in hours.items()],
            "traps": {"total": len(traps), "online": online}}


class EventLabelIn(BaseModel):
    label: str = Field(min_length=1, max_length=64)


@router.post("/events/{event_id}/label")
def label_event(event_id: int, body: EventLabelIn,
                user: User = Depends(auth.require_role("admin", "operator")),
                db: Session = Depends(get_db)):
    """Обратная связь оператора: фиксация корректной метки класса действия (FR-Feedback)."""
    ev = db.get(Event, event_id)
    if not ev:
        raise HTTPException(404, "Событие не найдено")
    lbl = EventLabel(event_id=ev.id, label=body.label.strip(), operator=user.username)
    db.add(lbl)
    db.commit()
    return {"status": "ok", "id": lbl.id, "event_id": ev.id, "label": lbl.label, "operator": lbl.operator}


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
            sess = auth.load_session_token(db, settings, token, "full")
            return sess is not None and "events.view" in auth.permissions_of(db, sess.user)

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
