"""Откуда атакуют: источники с геолокацией, ASN и счётчиками — для карты и списка в панели."""
from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, BackgroundTasks, Depends, Query, Request
from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from .. import auth, geo
from ..db import get_db
from ..models import Event, User, utcnow

router = APIRouter(prefix="/api", tags=["sources"])

PERIODS = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30)}


@router.get("/sources")
def sources(request: Request, background: BackgroundTasks, period: str = Query("24h", pattern="^(24h|7d|30d|all)$"),
            limit: int = Query(200, ge=1, le=500), _: User = Depends(auth.require_perm("events.view")), db: Session = Depends(get_db)):
    """Источники атак за период: события, попытки входа, команды, затронутые ловушки, максимальная опасность."""
    cond = [Event.src_ip != "", Event.type != "alert"]
    if period in PERIODS:
        cond.append(Event.ts >= utcnow() - PERIODS[period])
    rows = db.execute(
        select(Event.src_ip, func.count(), func.min(Event.ts), func.max(Event.ts),
               func.sum(case((Event.type == "auth_attempt", 1), else_=0)),
               func.sum(case((Event.type == "command", 1), else_=0)),
               func.sum(case((Event.type == "honeytoken", 1), else_=0)),
               func.count(func.distinct(Event.trap_id)), func.max(Event.threat_score))
        .where(*cond).group_by(Event.src_ip).order_by(func.count().desc()).limit(limit)).all()
    geo_map = geo.cached(db, {r[0] for r in rows})
    settings = auth.settings_of(request)
    missing = {r[0] for r in rows if r[0] not in geo_map or (geo_map[r[0]] or {}).get("lat") is None}
    if settings.geoip_url and missing:
        background.add_task(geo.enrich, request.app.state.session_factory, settings.geoip_url, missing)

    items, countries = [], {}
    for ip, n, first, last, auth_n, cmd_n, tok_n, traps_n, score in rows:
        g = geo_map.get(ip)
        items.append({"ip": ip, "events": n, "auth_attempts": int(auth_n or 0), "commands": int(cmd_n or 0),
                      "honeytokens": int(tok_n or 0), "traps": traps_n, "max_score": score,
                      "first_seen": first.isoformat() + "Z", "last_seen": last.isoformat() + "Z", "geo": g})
        if g and g["country_code"] not in ("", "--"):
            c = countries.setdefault(g["country_code"], {"country_code": g["country_code"], "country": g["country"],
                                                         "events": 0, "ips": 0})
            c["events"] += n
            c["ips"] += 1
    return {"period": period, "items": items, "countries": sorted(countries.values(), key=lambda c: -c["events"]),
            "unlocated": sum(1 for i in items if not i["geo"] or i["geo"].get("lat") is None)}
