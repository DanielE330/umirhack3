import hmac
import os

from fastapi import Header, HTTPException


def internal_only(x_internal_token: str = Header(default="")):
    """
    Управление ловушками доступно только центру HoneyForge (межсервисный токен ORCH_TOKEN).
    Без настроенного токена эндпоинты закрыты целиком, а не открыты всем.
    """
    expected = os.environ.get("ORCH_TOKEN", "")
    if not expected or not hmac.compare_digest(x_internal_token, expected):
        raise HTTPException(status_code=401, detail="Unauthorized")
