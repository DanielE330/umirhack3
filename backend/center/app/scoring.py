"""Фоновая оценка событий/сессий через HoneyMind.

Запускается ПОСЛЕ ingest_events()/db.commit() (app/routers/agent_api.py), в ограниченном пуле
потоков — поток событий от агентов не должен копить неограниченное число фоновых задач и забивать
память, если HoneyMind медленный или недоступен. Падение/недоступность HoneyMind не должно ронять
приём событий: при ошибке/таймауте событие остаётся с threat_score = NULL.
"""
from __future__ import annotations

import logging
import time
from concurrent.futures import Executor, ThreadPoolExecutor
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from .honeymind import HoneyMind
from .models import Event, SessionAssessment
from .orchestrator import Orchestrator

log = logging.getLogger("honeyforge.center.scoring")

ALERT_THRESHOLD = 60
# Ограничиваем и параллелизм, и число попыток — иначе медленный/недоступный HoneyMind копит
# неограниченно много фоновых задач на потоке событий от агентов.
MAX_WORKERS = 8
RETRY_DELAYS_SECONDS = [1, 3, 8]

# Синтетические события центра (бруфорс-алерт) — не от атакующего, HoneyMind не оценивает их.
SKIP_PREDICT_TYPES = {"alert"}
# Для перебора паролей уже есть отдельный алерт center (bruteforce, см. services._make_alerts) —
# не дублируем уведомление через HoneyMind на каждую попытку входа.
SKIP_THREAT_ALERT_TYPES = {"auth_attempt"}

_executor: Executor = ThreadPoolExecutor(max_workers=MAX_WORKERS, thread_name_prefix="honeymind-score")


def _event_payload(view: dict[str, Any]) -> dict[str, Any]:
    """Тело запроса /predict — поля Event центра (см. honeymind/honeymind/adapter.py, схема «Event центра»)."""
    return {
        "type": view.get("type"),
        "command": view.get("command"),
        "username": view.get("username"),
        "password": view.get("password"),
        "session_id": view.get("session_id"),
        "ts": view.get("ts"),
        "data": view.get("data"),
    }


def submit_score_event(session_factory: sessionmaker[Session], honeymind: HoneyMind,
                        orchestrator: Orchestrator, event_view: dict[str, Any]):
    """Планирует фоновую оценку одного события. Не блокирует вызывающий код.

    Возвращает Future (или None, если оценка не планировалась) — пустой результат вызывающий код
    игнорирует, тестам он даёт возможность дождаться завершения фоновой задачи.
    """
    if event_view.get("type") in SKIP_PREDICT_TYPES or not honeymind.url:
        return None  # HoneyMind не настроен (HF_HONEYMIND_URL пуст) — это не сбой, повторять нечего
    return _executor.submit(_score_event, session_factory, honeymind, orchestrator, event_view)


def submit_session_assessment(session_factory: sessionmaker[Session], honeymind: HoneyMind, session_id: str):
    """Планирует фоновую оценку is_human по событию session_end. Не блокирует вызывающий код (см. submit_score_event)."""
    if not session_id or not honeymind.url:
        return None
    return _executor.submit(_assess_session, session_factory, honeymind, session_id)


def _score_event(session_factory: sessionmaker[Session], honeymind: HoneyMind,
                  orchestrator: Orchestrator, event_view: dict[str, Any]) -> None:
    payload = _event_payload(event_view)
    result = honeymind.predict(payload)
    if result is None:
        for delay in RETRY_DELAYS_SECONDS:
            time.sleep(delay)
            result = honeymind.predict(payload)
            if result is not None:
                break

    if result is None:
        log.warning("honeymind: событие %s осталось без оценки (сервис недоступен)", event_view.get("id"))
        return

    with session_factory() as db:
        ev = db.get(Event, event_view["id"])
        if ev is None:
            return
        ev.threat_score = result.get("threat_score")
        ev.category = result.get("category")
        ev.needs_review = result.get("needs_review")
        ev.honeymind_result = result
        db.commit()

    threat_score = result.get("threat_score") or 0
    event_type = event_view.get("type")
    if threat_score >= ALERT_THRESHOLD and event_type not in SKIP_THREAT_ALERT_TYPES:
        _notify_threat(orchestrator, event_type, event_view.get("src_ip", ""), result)


def _notify_threat(orchestrator: Orchestrator, event_type: str, src_ip: str, result: dict[str, Any]) -> None:
    """Алерт в Telegram через существующий канал центр -> оркестратор -> send_alert.

    Передаём только поля ответа HoneyMind (summary собран из шаблонов, без текста атакующего —
    honeymind/README.md, раздел «Безопасность»), а не сырой payload события.
    """
    try:
        orchestrator.request("POST", "/", {
            "event_name": "honeymind_threat",
            "attacker_ip": src_ip or "",
            "properties": {
                "source_event_type": event_type,
                "category": result.get("category"),
                "threat_score": result.get("threat_score"),
                "summary": result.get("summary", ""),
            },
        }, timeout=10, base="/api/v1/notify")
    except Exception:
        pass  # алерт вторичен: оценка уже сохранена в БД


def _assess_session(session_factory: sessionmaker[Session], honeymind: HoneyMind, session_id: str) -> None:
    with session_factory() as db:
        rows = db.scalars(select(Event).where(Event.session_id == session_id).order_by(Event.ts)).all()
        events = [_event_payload({
            "type": r.type, "command": r.command, "username": r.username, "password": r.password,
            "session_id": r.session_id, "ts": r.ts.isoformat() + "Z", "data": r.data,
        }) for r in rows]
        last_src_ip = rows[-1].src_ip if rows else ""
        trap_id = rows[-1].trap_id if rows else None

    if not events:
        return

    result = honeymind.predict_session(events)
    if result is None:
        log.warning("honeymind: сессия %s осталась без оценки is_human (сервис недоступен)", session_id)
        return

    with session_factory() as db:
        assessment = db.get(SessionAssessment, session_id)
        if assessment is None:
            assessment = SessionAssessment(session_id=session_id)
            db.add(assessment)
        assessment.trap_id = trap_id
        assessment.src_ip = last_src_ip
        assessment.is_human = result.get("is_human")
        assessment.human_probability = result.get("human_probability")
        assessment.human_method = result.get("human_method")
        assessment.human_reason = result.get("human_reason")
        assessment.script_seen_before = result.get("script_seen_before")
        assessment.result = result
        db.commit()
