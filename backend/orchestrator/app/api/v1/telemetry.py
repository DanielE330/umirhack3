from fastapi import APIRouter, Request, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.database import get_db
from app.models.models import Event
from app.schemas.telemetry import TelemetryEvent
from app.services.telegram_service import send_alert
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
        
        # Создаем запись в базе данных PostgreSQL
        new_event = Event(
            trap_id=None, # Привязку ловушек сделаем позже
            attacker_ip=attacker_ip,
            event_type=event.event_name,
            payload=event.properties,
            timestamp=datetime.utcnow()
        )
        db.add(new_event)
        await db.commit() # Сохраняем!
        
        print(f"🚨 [БД] Атака '{event.event_name}' от {attacker_ip} успешно сохранена в базу!")
        
        # Отправляем алерт в Telegram (если токен настроен)
        import asyncio
        asyncio.create_task(send_alert(event.event_name, attacker_ip, event.properties))
        
    except Exception as e:
        print(f"Ошибка сохранения лога в БД: {e}")
        # Ошибку не прокидываем дальше, чтобы не спалиться перед хакером
    
    # Возвращаем стандартный ответ трекера (чтобы хакер ничего не заподозрил, если перехватит трафик)
    return {"status": "success", "tracked": True}
