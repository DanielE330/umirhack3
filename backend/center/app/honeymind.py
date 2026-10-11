"""Клиент HoneyMind (AI-аналитика событий, отдельный сервис только во внутренней сети).

В отличие от Orchestrator (app/orchestrator.py) — никогда не бросает исключение: вызывающий код
(app/scoring.py) работает в фоне, после того как событие уже сохранено и ответ агенту отправлен,
поэтому падение/недоступность HoneyMind не должна ничего ронять — просто нет оценки (None).
"""
from __future__ import annotations

from typing import Any

import httpx

from .config import Settings


class HoneyMind:
    def __init__(self, settings: Settings, transport: httpx.BaseTransport | None = None):
        self.url = settings.honeymind_url.rstrip("/")
        self.token = settings.honeymind_token
        self.timeout = settings.honeymind_timeout
        self.transport = transport  # подмена в тестах

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}

    def predict(self, event: dict[str, Any]) -> dict[str, Any] | None:
        """POST /predict — событие в формате Event центра (type/command/username/password/session_id/ts/data)."""
        if not self.url:
            return None
        try:
            with httpx.Client(transport=self.transport, timeout=self.timeout) as client:
                resp = client.post(f"{self.url}/predict", json=event, headers=self._headers())
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPError:
            return None

    def predict_session(self, events: list[dict[str, Any]]) -> dict[str, Any] | None:
        """POST /session — вызывается реже и не на хот-пути приёма событий, таймаут шире."""
        if not self.url:
            return None
        try:
            with httpx.Client(transport=self.transport, timeout=max(self.timeout * 5, 2.0)) as client:
                resp = client.post(f"{self.url}/session", json={"events": events}, headers=self._headers())
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPError:
            return None

    def predict_batch(self, events: list[dict[str, Any]]) -> list[dict[str, Any]] | None:
        """POST /predict/batch — до 200 событий за один запрос."""
        if not self.url or not events:
            return None
        try:
            with httpx.Client(transport=self.transport, timeout=max(self.timeout * 3, 5.0)) as client:
                resp = client.post(f"{self.url}/predict/batch", json={"events": events}, headers=self._headers())
            resp.raise_for_status()
            data = resp.json()
            return data.get("results")
        except httpx.HTTPError:
            return None

    def get_model_version(self) -> str:
        """GET /health -> version (по умолчанию honeymind-3)."""
        if not self.url:
            return "honeymind-3"
        try:
            with httpx.Client(transport=self.transport, timeout=self.timeout) as client:
                resp = client.get(f"{self.url}/health")
            if resp.status_code == 200:
                return resp.json().get("version", "honeymind-3")
        except Exception:
            pass
        return "honeymind-3"
