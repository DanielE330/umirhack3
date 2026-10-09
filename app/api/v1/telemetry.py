from fastapi import APIRouter, Request
from app.schemas.telemetry import TelemetryEvent

router = APIRouter()

# Требование MASK-2: Неприметный endpoint. 
# Для стороннего наблюдателя это выглядит как безобидный сбор статистики (например, кликов по сайту).
@router.post("/analytics/track")
async def collect_telemetry(event: TelemetryEvent, request: Request):
    """
    Скрытый канал приема телеметрии от ловушек.
    """
    # TODO: В следующей фазе здесь будет сохранение в PostgreSQL
    
    print("="*50)
    print(f"🚨 [ТЕЛЕМЕТРИЯ] Активность в ловушке: {event.client_id}")
    print(f"Тип события: {event.event_name}")
    print(f"IP Атакующего и детали: {event.properties}")
    print("="*50)
    
    # Возвращаем стандартный ответ трекера (чтобы хакер ничего не заподозрил, если перехватит трафик)
    return {"status": "success", "tracked": True}
