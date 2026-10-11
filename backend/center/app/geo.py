"""Геолокация и ASN источников атак. Данные берутся из публичного сервиса (по умолчанию ip-api.com, без ключа),
кэшируются в таблице ip_info и запрашиваются в фоне: сбой сервиса не мешает приёму событий."""
from __future__ import annotations

import ipaddress
import json
import threading
import urllib.request
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from .models import IpInfo, utcnow

TTL = timedelta(days=7)
RETRY_AFTER = timedelta(minutes=10)  # после неудачи тот же IP повторно не спрашиваем сразу
_failed: dict[str, object] = {}
_lock = threading.Lock()


def is_public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def info_view(row: IpInfo | None) -> dict | None:
    if row is None:
        return None
    return {"country_code": row.country_code, "country": row.country, "city": row.city, "asn": row.asn, "org": row.org,
            "lat": row.lat, "lon": row.lon}


def cached(db: Session, ips: set[str]) -> dict[str, dict]:
    """Уже известные данные по IP (без обращений к сети)."""
    ips = {i for i in ips if i}
    if not ips:
        return {}
    return {r.ip: info_view(r) for r in db.scalars(select(IpInfo).where(IpInfo.ip.in_(ips)))}


def _fetch(url: str, ips: list[str]) -> dict[str, dict]:
    body = json.dumps([{"query": ip, "fields": "status,country,countryCode,city,lat,lon,as,asname,query"} for ip in ips]).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=8) as resp:  # noqa: S310 — адрес задаёт администратор
        rows = json.loads(resp.read())
    return {r["query"]: r for r in rows if r.get("status") == "success"}


def enrich(factory: sessionmaker, url: str, ips: set[str]) -> None:
    """Дописывает в ip_info данные по новым IP. Вызывается из фоновой задачи."""
    if not url:
        return
    now = utcnow()
    with factory() as db:
        have = {r.ip: r for r in db.scalars(select(IpInfo).where(IpInfo.ip.in_([i for i in ips if i])))}
        todo = []
        for ip in ips:
            if not ip:
                continue
            row = have.get(ip)
            if not is_public(ip):
                if row is None:
                    db.add(IpInfo(ip=ip, country_code="--", country="Локальная сеть", org="Частный адрес"))
                continue
            if row is not None and now - row.fetched_at < TTL and row.lat is not None:
                continue
            with _lock:
                if _failed.get(ip) and now - _failed[ip] < RETRY_AFTER:
                    continue
            todo.append(ip)
        for i in range(0, len(todo), 100):
            chunk = todo[i:i + 100]
            try:
                found = _fetch(url, chunk)
            except Exception as exc:  # сеть недоступна, лимит сервиса и т. п.
                print(f"⚠️ [GeoIP] запрос не удался: {exc}", flush=True)
                with _lock:
                    _failed.update({ip: now for ip in chunk})
                continue
            for ip in chunk:
                r = found.get(ip)
                if r is None:
                    with _lock:
                        _failed[ip] = now
                    continue
                asn = (r.get("as") or "").split(" ", 1)
                row = have.get(ip) or IpInfo(ip=ip)
                row.country_code, row.country, row.city = r.get("countryCode", ""), r.get("country", ""), r.get("city", "")
                row.asn, row.org, row.fetched_at = asn[0], r.get("asname") or (asn[1] if len(asn) > 1 else ""), now
                row.lat, row.lon = r.get("lat"), r.get("lon")
                db.merge(row)
        db.commit()
