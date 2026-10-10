"""Клиент HoneyMind (AI-аналитика событий ловушек, сервис только во внутренней сети).

Контракт: см. honeymind/README.md. Любая ошибка/таймаут → None, вызывающий код сохраняет
событие без оценки и дооценивает его фоном (приём событий не должен ждать HoneyMind).
"""
import os
from typing import Any

import httpx

HONEYMIND_URL = os.getenv("HONEYMIND_URL", "http://honeymind:8001")
HONEYMIND_TOKEN = os.getenv("HONEYMIND_TOKEN", "")
# Типичный ответ ~4 мс (см. README), таймаут держим небольшим, чтобы не задерживать прием событий.
HONEYMIND_TIMEOUT = float(os.getenv("HONEYMIND_TIMEOUT", "0.4"))


def _headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {HONEYMIND_TOKEN}"} if HONEYMIND_TOKEN else {}


async def predict(event_type: str, payload: dict[str, Any]) -> dict[str, Any] | None:
    """POST /predict — оценка одного события. None при ошибке/таймауте."""
    try:
        async with httpx.AsyncClient(base_url=HONEYMIND_URL, timeout=HONEYMIND_TIMEOUT, headers=_headers()) as client:
            resp = await client.post("/predict", json={"event_type": event_type, "payload": payload})
            resp.raise_for_status()
            return resp.json()
    except httpx.HTTPError:
        return None


async def predict_session(events: list[dict[str, Any]]) -> dict[str, Any] | None:
    """POST /session — оценка сессии целиком (is_human). Вызывается реже и не на хот-пути приёма событий,
    поэтому таймаут шире, чем у /predict."""
    try:
        async with httpx.AsyncClient(base_url=HONEYMIND_URL, timeout=max(HONEYMIND_TIMEOUT * 5, 2.0),
                                      headers=_headers()) as client:
            resp = await client.post("/session", json={"events": events})
            resp.raise_for_status()
            return resp.json()
    except httpx.HTTPError:
        return None
