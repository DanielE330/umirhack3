"""Приведение входящих событий к единому виду.

В проекте сейчас три несовместимые схемы события (и четвёртая — Cowrie), поэтому HoneyMind принимает любую:
  1) таблица Ростика:   {"event_type": "command_executed", "payload": {"command": "..."} | "<json-строка>", ...}
  2) плоский payload:   {"command": "..."} | {"username": "...", "password": "..."} | {"url": "...", "file_hash": "..."}
  3) Event центра:      {"type": "command", "command": "...", "username": ..., "data": {...}, "ts": ...}
  4) Cowrie:            {"eventid": "cowrie.command.input", "input": "..."}

Любой из атрибутов атакующий контролирует целиком → всё приводится к str и обрезается.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

MAX_FIELD = 4096

KIND_COMMAND, KIND_LOGIN, KIND_DOWNLOAD = "command", "login", "download"
KIND_HONEYTOKEN, KIND_HTTP, KIND_CONNECT, KIND_END, KIND_OTHER = "honeytoken", "http", "connect", "end", "other"

_TYPE_MAP = {
    # таблица Ростика
    "command_executed": KIND_COMMAND, "ssh_login_attempt": KIND_LOGIN, "malware_download": KIND_DOWNLOAD,
    # Event центра
    "command": KIND_COMMAND, "auth_attempt": KIND_LOGIN, "payload": KIND_DOWNLOAD, "honeytoken": KIND_HONEYTOKEN,
    "http_request": KIND_HTTP, "connect": KIND_CONNECT, "session_end": KIND_END, "alert": KIND_OTHER,
    # Cowrie
    "cowrie.command.input": KIND_COMMAND, "cowrie.command.success": KIND_COMMAND, "cowrie.command.failed": KIND_COMMAND,
    "cowrie.login.failed": KIND_LOGIN, "cowrie.login.success": KIND_LOGIN,
    "cowrie.session.file_download": KIND_DOWNLOAD, "cowrie.session.file_upload": KIND_DOWNLOAD,
    "cowrie.session.connect": KIND_CONNECT, "cowrie.session.closed": KIND_END,
}


@dataclass
class CanonEvent:
    kind: str
    command: str | None = None
    username: str | None = None
    password: str | None = None
    url: str | None = None
    file_hash: str | None = None
    success: bool | None = None
    ts: datetime | None = None
    session_id: str | None = None
    src_ip: str | None = None
    raw_type: str | None = None
    client: str | None = None     # строка версии SSH-клиента (SSH-2.0-Go, SSH-2.0-OpenSSH_9.6 …), если ловушка её прислала
    action: str | None = None     # planted / exfiltrated для honeytoken
    token_id: str | None = None   # идентификатор канареечного токена
    hassh: str | None = None      # отпечаток SSH-клиента (RFC 4253 / Salesforce HASSH)
    hassh_raw: str | None = None  # строка алгоритмов KEXINIT до хеширования
    category: str | None = None   # категория атаки (sqli, xss, lfi, rce, log4shell, wordpot, ransomware)
    threat_score: int | None = None # предварительная оценка опасности от ловушки


def _s(v: Any) -> str | None:
    if v is None:
        return None
    if isinstance(v, (dict, list)):
        try:
            v = json.dumps(v, ensure_ascii=False)
        except (TypeError, ValueError):
            v = str(v)
    return str(v)[:MAX_FIELD]


def _parse_ts(v: Any) -> datetime | None:
    if v is None or v == "":
        return None
    try:
        if isinstance(v, (int, float)):
            return datetime.fromtimestamp(float(v), tz=timezone.utc)
        s = str(v).strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (ValueError, OverflowError, OSError):
        return None


def _as_dict(v: Any) -> dict:
    if isinstance(v, dict):
        return v
    if isinstance(v, str) and v.strip().startswith("{") and len(v) <= 65536:
        try:
            d = json.loads(v)
            return d if isinstance(d, dict) else {}
        except ValueError:
            return {}
    return {}


def _first(d: dict, *keys: str) -> Any:
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    return None


def canonicalize(obj: Any) -> CanonEvent:
    if not isinstance(obj, dict):
        return CanonEvent(kind=KIND_OTHER)
    raw_type = _s(_first(obj, "event_type", "type", "eventid"))
    kind = _TYPE_MAP.get(raw_type or "")
    # детали: payload (Ростик) → data (центр) → корень объекта
    detail = {**obj, **_as_dict(obj.get("data")), **_as_dict(obj.get("payload"))}

    command = _first(detail, "command", "input", "cmd")
    username, password = _first(detail, "username", "user", "login"), _first(detail, "password", "pass", "passwd")
    url = _first(detail, "url", "outfile")
    client = _first(detail, "client_version", "ssh_client_version", "ssh_client", "client")
    if client is None and raw_type == "cowrie.client.version":
        client = detail.get("version")
    fhash = _first(detail, "file_hash", "shasum", "sha256", "hash")

    if kind is None:  # тип не указан → определяем по содержимому (плоский payload)
        if command is not None:
            kind = KIND_COMMAND
        elif url is not None or fhash is not None:
            kind = KIND_DOWNLOAD
        elif username is not None or password is not None:
            kind = KIND_LOGIN
        else:
            kind = KIND_OTHER
    # Тип «payload» агента HoneyForge — НЕ обязательно скачивание: это и попытка wget/curl в SSH-ловушке
    # (в command лежит строка команды), и сырые байты, присланные в TCP-ловушку (command = их печатный вид).
    # Поэтому, если есть текст команды и нет url/хэша, анализируем его как команду (правила + ML решат сами).
    if raw_type == "payload" and command is not None and url is None and fhash is None:
        kind = KIND_COMMAND
    # honeytoken в центре кладёт путь в поле command — оставляем как есть
    action = _first(detail, "action", "status")
    token_id = _first(detail, "token_id", "canary_token", "token")
    hassh = _first(detail, "hassh", "ssh_hassh")
    hassh_raw = _first(detail, "hassh_raw", "ssh_hassh_raw")
    category = _first(detail, "category", "attack_type")
    threat_score = _first(detail, "threat_score")
    if threat_score is not None:
        try:
            threat_score = int(threat_score)
        except (ValueError, TypeError):
            threat_score = None
    success = detail.get("success")
    if raw_type == "cowrie.login.success":
        success = True
    elif raw_type == "cowrie.login.failed":
        success = False
    return CanonEvent(
        kind=kind, command=_s(command), username=_s(username), password=_s(password), url=_s(url),
        file_hash=_s(fhash), success=success if isinstance(success, bool) else None,
        ts=_parse_ts(_first(obj, "timestamp", "ts", "received_at", "time")),
        session_id=_s(_first(obj, "session_id", "session")), src_ip=_s(_first(obj, "attacker_ip", "src_ip")),
        raw_type=raw_type, client=_s(client)[:200] if client is not None else None,
        action=_s(action), token_id=_s(token_id),
        hassh=_s(hassh), hassh_raw=_s(hassh_raw),
        category=_s(category), threat_score=threat_score,
    )
