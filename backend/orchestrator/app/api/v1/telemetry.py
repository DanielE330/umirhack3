import asyncio

from fastapi import APIRouter, Request, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.database import get_db
from app.models.models import Event
from app.schemas.telemetry import TelemetryEvent
from app.services.telegram_service import send_alert
from app.services.scoring import score_event, assess_session, SESSION_END_EVENT_TYPES
from datetime import datetime

router = APIRouter()

# Требование MASK-2: Неприметный endpoint.
# Для стороннего наблюдателя это выглядит как безобидный сбор статистики (например, кликов по сайту).
@router.post("/analytics/track")
async def collect_telemetry(event: TelemetryEvent, request: Request, db: AsyncSession = Depends(get_db)):
    """
    Скрытый канал приема телеметрии от ловушек.
    """
    try:
        # Извлекаем IP атакующего (если он есть в payload)
        attacker_ip = event.properties.get("src_ip", "unknown")
        session_id = event.properties.get("session_id") or event.properties.get("session")

        # Создаем запись в базе данных PostgreSQL. threat_score/category/needs_review остаются
        # NULL — их выставит фоновая оценка HoneyMind (см. ниже), падение которой не должно
        # ронять приём события.
        new_event = Event(
            trap_id=None, # Привязку ловушек сделаем позже
            attacker_ip=attacker_ip,
            event_type=event.event_name,
            payload=event.properties,
            session_id=session_id,
            timestamp=datetime.utcnow()
        )
        db.add(new_event)
        await db.commit() # Сохраняем!
        await db.refresh(new_event)

        print(f"🚨 [БД] Атака '{event.event_name}' от {attacker_ip} успешно сохранена в базу!")

        # Отправляем алерт в Telegram (если токен настроен)
        asyncio.create_task(send_alert(event.event_name, attacker_ip, event.properties))

        # Оценка HoneyMind — асинхронно, не блокируя ответ трекеру (таймаут ~400 мс внутри
        # score_event; при ошибке он дооценит событие в фоне позже).
        asyncio.create_task(score_event(new_event.id, event.event_name, event.properties, attacker_ip))

        # Конец сессии (если агент сообщает session_id) → оценка «человек или бот» по всей сессии.
        if session_id and event.event_name in SESSION_END_EVENT_TYPES:
            asyncio.create_task(assess_session(session_id))

    except Exception as e:
        print(f"Ошибка сохранения лога в БД: {e}")
        # Ошибку не прокидываем дальше, чтобы не спалиться перед хакером

    # Возвращаем стандартный ответ трекера (чтобы хакер ничего не заподозрил, если перехватит трафик)
    return {"status": "success", "tracked": True}
