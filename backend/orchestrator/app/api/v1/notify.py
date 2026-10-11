from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.api.deps import internal_only
from app.services.telegram_service import send_alert, send_message

router = APIRouter(dependencies=[Depends(internal_only)])


class Notice(BaseModel):
    event_name: str = Field(max_length=64)
    attacker_ip: str = Field(default="", max_length=64)
    properties: Dict[str, Any] = Field(default_factory=dict)
    chat_ids: list[str] = Field(default_factory=list)


@router.post("/")
async def notify(body: Notice):
    """Алерты центра (перебор паролей, honeytoken) — в Telegram через сервис уведомлений."""
    await send_alert(body.event_name, body.attacker_ip or "—", body.properties, chat_ids=body.chat_ids)
    return {"status": "sent"}



class Direct(BaseModel):
    chat_id: str = Field(min_length=1, max_length=64, pattern=r"^-?\d+$")
    text: str = Field(min_length=1, max_length=1000)


@router.post("/direct")
async def direct(body: Direct):
    """Личное сообщение оператору от центра (например, код сброса пароля)."""
    if not await send_message(body.chat_id, body.text):
        raise HTTPException(502, "Telegram недоступен или бот не настроен")
    return {"status": "sent"}
