from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.db.database import get_db
from app.models.models import Event

router = APIRouter()

@router.get("/")
async def get_recent_events(limit: int = 20, db: AsyncSession = Depends(get_db)):
    """
    Получить ленту последних атак для фронтенда.
    """
    # Достаем последние события из БД, сортируя по времени (свежие сверху)
    query = select(Event).order_by(Event.timestamp.desc()).limit(limit)
    result = await db.execute(query)
    events = result.scalars().all()
    
    # Формируем красивый JSON ответ для фронтенда
    response = []
    for e in events:
        response.append({
            "id": e.id,
            "timestamp": e.timestamp.isoformat(),
            "attacker_ip": e.attacker_ip,
            "event_type": e.event_type,
            "payload": e.payload
        })
        
    return response
