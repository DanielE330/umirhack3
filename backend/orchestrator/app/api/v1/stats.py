from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from datetime import datetime, timedelta
from app.db.database import get_db
from app.models.models import Event, Trap

router = APIRouter()

@router.get("/")
async def get_dashboard_stats(db: AsyncSession = Depends(get_db)):
    """Эндпоинт для дашборда (фронтенда)"""
    
    # 1. Считаем сколько всего ловушек в базе данных
    traps_query = await db.execute(select(func.count(Trap.id)))
    online_traps = traps_query.scalar() or 0
    
    # 2. Считаем события за последние 24 часа
    yesterday = datetime.utcnow() - timedelta(days=1)
    events_query = await db.execute(
        select(func.count(Event.id)).where(Event.timestamp >= yesterday)
    )
    total_events = events_query.scalar() or 0
    
    # 3. Попытки авторизации (подбор паролей)
    auth_query = await db.execute(
        select(func.count(Event.id)).where(Event.event_type.in_(["ssh_login", "auth_attempt"]))
    )
    auth_attempts = auth_query.scalar() or 0
    
    # 4. Алерты (опасные события: хакер выполнил команду)
    alert_query = await db.execute(
        select(func.count(Event.id)).where(Event.event_type.in_(["command_executed", "malware_download"]))
    )
    alerts = alert_query.scalar() or 0

    # Возвращаем ровно в том виде, в котором ожидает веб-интерфейс
    return {
        "events_24h": total_events,
        "traps_online": online_traps,
        "auth_attempts": auth_attempts,
        "alerts": alerts
    }
