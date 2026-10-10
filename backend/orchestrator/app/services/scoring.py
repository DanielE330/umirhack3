"""Фоновая оценка событий/сессий через HoneyMind. Запускается через asyncio.create_task
из telemetry.py и никогда не блокирует и не роняет приём событий — падение HoneyMind
означает только то, что threat_score/is_human остаются NULL."""
import asyncio
import logging
from datetime import datetime

from sqlalchemy import select

from app.db.database import AsyncSessionLocal
from app.models.models import Event, SessionAssessment
from app.services import honeymind_client
from app.services.telegram_service import send_threat_alert

log = logging.getLogger("honeyforge.scoring")

ALERT_THRESHOLD = 60
# Если первая попытка (внутри honeymind_client.predict, таймаут ~400 мс) не удалась —
# сервис, вероятно, временно недоступен или перегружен; дожидаемся его в фоне.
RETRY_DELAYS_SECONDS = [2, 5, 15, 30, 60]

# Какие типы событий считаем концом сессии (разные схемы событий в проекте).
SESSION_END_EVENT_TYPES = {"session_end", "cowrie.session.closed", "session_closed", "disconnect"}


async def score_event(event_id: int, event_type: str, payload: dict, attacker_ip: str) -> None:
    result = await honeymind_client.predict(event_type, payload)
    if result is None:
        for delay in RETRY_DELAYS_SECONDS:
            await asyncio.sleep(delay)
            result = await honeymind_client.predict(event_type, payload)
            if result is not None:
                break

    if result is None:
        log.warning("honeymind: событие %s осталось без оценки (сервис недоступен)", event_id)
        return

    await _save_event_score(event_id, result)

    if result.get("threat_score", 0) >= ALERT_THRESHOLD:
        await send_threat_alert(event_type, attacker_ip, result)


async def _save_event_score(event_id: int, result: dict) -> None:
    async with AsyncSessionLocal() as db:
        ev = await db.get(Event, event_id)
        if ev is None:
            return
        ev.threat_score = result.get("threat_score")
        ev.category = result.get("category")
        ev.needs_review = result.get("needs_review")
        ev.honeymind_result = result
        await db.commit()


async def assess_session(session_id: str) -> None:
    """Вызывается по завершении сессии (событие из SESSION_END_EVENT_TYPES):
    собирает все события с этим session_id и запрашивает /session, чтобы получить is_human."""
    async with AsyncSessionLocal() as db:
        rows = (
            await db.execute(
                select(Event).where(Event.session_id == session_id).order_by(Event.timestamp)
            )
        ).scalars().all()

    if not rows:
        return

    events = [
        {"event_type": r.event_type, "payload": r.payload, "timestamp": r.timestamp.isoformat()}
        for r in rows
    ]
    result = await honeymind_client.predict_session(events)
    if result is None:
        log.warning("honeymind: сессия %s осталась без оценки is_human (сервис недоступен)", session_id)
        return

    async with AsyncSessionLocal() as db:
        assessment = await db.get(SessionAssessment, session_id)
        if assessment is None:
            assessment = SessionAssessment(session_id=session_id)
            db.add(assessment)
        assessment.attacker_ip = rows[-1].attacker_ip
        assessment.is_human = result.get("is_human")
        assessment.human_probability = result.get("human_probability")
        assessment.human_method = result.get("human_method")
        assessment.human_reason = result.get("human_reason")
        assessment.script_seen_before = result.get("script_seen_before")
        assessment.result = result
        assessment.updated_at = datetime.utcnow()
        await db.commit()
