from typing import Any, Dict

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.api.deps import internal_only
from app.services.telegram_service import send_alert

router = APIRouter(dependencies=[Depends(internal_only)])


class Notice(BaseModel):
    event_name: str = Field(max_length=64)
    attacker_ip: str = Field(default="", max_length=64)
    properties: Dict[str, Any] = Field(default_factory=dict)


@router.post("/")
async def notify(body: Notice):
    """Алерты центра (перебор паролей, honeytoken) — в Telegram через сервис уведомлений."""
    await send_alert(body.event_name, body.attacker_ip or "—", body.properties)
    return {"status": "sent"}
