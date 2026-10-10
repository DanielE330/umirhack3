from pydantic import BaseModel
from typing import Dict, Any

class TelemetryEvent(BaseModel):
    """
    Схема данных замаскирована под обычные события фронтенд-аналитики (например, Google Analytics).
    """
    event_name: str            # Название события (например: 'user_login', 'page_view')
    client_id: str             # Замаскированный ID ловушки (trap_id)
    timestamp: str             # Время события
    properties: Dict[str, Any] # Здесь прячутся реальные данные об атаке (IP хакера, пароли, команды)
