"""Фоновая оценка событий/сессий через HoneyMind.

Запускается ПОСЛЕ ingest_events()/db.commit() (app/routers/agent_api.py), в ограниченном пуле
потоков — поток событий от агентов не должен копить неограниченное число фоновых задач и забивать
память, если HoneyMind медленный или недоступен. Падение/недоступность HoneyMind не должно ронять
приём событий: при ошибке/таймауте событие остаётся с threat_score = NULL.
"""
from __future__ import annotations

import logging
import threading
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


def submit_session_assessment(session_factory: sessionmaker[Session], honeymind: HoneyMind,
                              session_id: str, orchestrator: Orchestrator | None = None):
    """Планирует фоновую оценку is_human по событию session_end. Не блокирует вызывающий код (см. submit_score_event)."""
    if not session_id or not honeymind.url:
        return None
    return _executor.submit(_assess_session, session_factory, honeymind, session_id, orchestrator)


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


def _assess_session(session_factory: sessionmaker[Session], honeymind: HoneyMind, session_id: str,
                    orchestrator: Orchestrator | None = None) -> None:
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
        assessment.threat_score = result.get("threat_score")
        assessment.download_then_execute = result.get("download_then_execute")
        assessment.ssh_client = result.get("ssh_client")
        assessment.result = result
        db.commit()

    threat_score = result.get("threat_score") or 0
    download_then_exec = bool(result.get("download_then_execute"))
    if orchestrator and (download_then_exec or threat_score >= ALERT_THRESHOLD):
        _notify_threat(orchestrator, "session", last_src_ip, result)


def rescore_unscored_events(
    session_factory: sessionmaker[Session],
    honeymind: HoneyMind,
    orchestrator: Orchestrator | None = None,
    limit: int = 200,
) -> int:
    """Фоновая дооценка событий с threat_score IS NULL (не больше limit за проход, через POST /predict/batch)."""
    if not honeymind.url:
        return 0

    with session_factory() as db:
        events = db.scalars(
            select(Event)
            .where(Event.threat_score.is_(None), Event.type.not_in(SKIP_PREDICT_TYPES))
            .order_by(Event.id.asc())
            .limit(limit)
        ).all()
        if not events:
            return 0
        event_ids = [e.id for e in events]
        payloads = [_event_payload({
            "type": e.type, "command": e.command, "username": e.username, "password": e.password,
            "session_id": e.session_id, "ts": e.ts.isoformat() + "Z" if e.ts else "", "data": e.data,
        }) for e in events]

    results = honeymind.predict_batch(payloads)
    if results is None or len(results) != len(event_ids):
        log.warning("honeymind: batch predict failed or returned incomplete results")
        return 0

    alerts_to_send = []
    with session_factory() as db:
        scored = 0
        for ev_id, res in zip(event_ids, results):
            ev = db.get(Event, ev_id)
            if not ev:
                continue
            ev.threat_score = res.get("threat_score")
            ev.category = res.get("category")
            ev.needs_review = res.get("needs_review")
            ev.honeymind_result = res
            scored += 1
            threat_score = ev.threat_score or 0
            if orchestrator and threat_score >= ALERT_THRESHOLD and ev.type not in SKIP_THREAT_ALERT_TYPES:
                alerts_to_send.append((ev.type, ev.src_ip or "", res))
        db.commit()

    if orchestrator:
        for ev_type, src_ip, res in alerts_to_send:
            _notify_threat(orchestrator, ev_type, src_ip, res)

    return scored


def _background_rescorer_loop(
    session_factory: sessionmaker[Session],
    honeymind: HoneyMind,
    orchestrator: Orchestrator,
    interval_seconds: float = 60.0,
    stop_event: threading.Event | None = None,
) -> None:
    while not (stop_event and stop_event.is_set()):
        if stop_event:
            if stop_event.wait(interval_seconds):
                break
        else:
            time.sleep(interval_seconds)
        try:
            rescore_unscored_events(session_factory, honeymind, orchestrator, limit=200)
        except Exception as exc:
            log.warning("Ошибка фоновой дооценки событий: %s", exc)


def start_background_rescorer(
    session_factory: sessionmaker[Session],
    honeymind: HoneyMind,
    orchestrator: Orchestrator,
    interval_seconds: float = 60.0,
) -> tuple[threading.Thread, threading.Event] | None:
    """Запускает фоновый поток дооценки (раз в минуту). Возвращает (поток, stop_event)."""
    if not honeymind.url:
        return None
    stop_event = threading.Event()
    t = threading.Thread(
        target=_background_rescorer_loop,
        args=(session_factory, honeymind, orchestrator, interval_seconds, stop_event),
        daemon=True,
        name="honeymind-rescorer",
    )
    t.start()
    return t, stop_event


def rescore_events_cli(
    session_factory: sessionmaker[Session],
    honeymind: HoneyMind,
    target_version: str | None = None,
    batch_size: int = 200,
) -> int:
    """CLI rescore: переоценка событий со старой model_version."""
    if not target_version:
        target_version = honeymind.get_model_version()
    print(f"Целевая версия модели: {target_version}")

    total_rescored = 0
    while True:
        with session_factory() as db:
            events = db.scalars(
                select(Event)
                .where(Event.type.not_in(SKIP_PREDICT_TYPES))
                .order_by(Event.id.asc())
            ).all()

            batch_events = []
            for e in events:
                hm_res = e.honeymind_result
                cur_ver = hm_res.get("model_version") if isinstance(hm_res, dict) else None
                if cur_ver != target_version:
                    batch_events.append(e)
                    if len(batch_events) >= batch_size:
                        break

            if not batch_events:
                break

            event_ids = [e.id for e in batch_events]
            payloads = [_event_payload({
                "type": e.type, "command": e.command, "username": e.username, "password": e.password,
                "session_id": e.session_id, "ts": e.ts.isoformat() + "Z" if e.ts else "", "data": e.data,
            }) for e in batch_events]

        results = honeymind.predict_batch(payloads)
        if results is None or len(results) != len(event_ids):
            print("Ошибка: HoneyMind недоступен или вернул некорректный ответ")
            break

        with session_factory() as db:
            for ev_id, res in zip(event_ids, results):
                ev = db.get(Event, ev_id)
                if not ev:
                    continue
                ev.threat_score = res.get("threat_score")
                ev.category = res.get("category")
                ev.needs_review = res.get("needs_review")
                ev.honeymind_result = res
            db.commit()

        total_rescored += len(event_ids)
        print(f"Переоценено {total_rescored} событий...")

    return total_rescored
