"""Клиент оркестратора Proxmox (отдельный микросервис). Центр — единственный, кто к нему ходит."""
from __future__ import annotations

import httpx
from fastapi import HTTPException

from .config import Settings


class Orchestrator:
    def __init__(self, settings: Settings, transport: httpx.BaseTransport | None = None):
        self.url = settings.orchestrator_url.rstrip("/")
        self.token = settings.orchestrator_token
        self.transport = transport  # подмена в тестах

    def request(self, method: str, path: str, json: dict | None = None, timeout: float = 30.0,
                base: str = "/api/v1/machines"):
        if not self.url or not self.token:
            raise HTTPException(503, "Оркестратор Proxmox не настроен")
        try:
            with httpx.Client(transport=self.transport, timeout=timeout) as client:
                resp = client.request(method, f"{self.url}{base}{path}", json=json,
                                      headers={"X-Internal-Token": self.token})
        except httpx.HTTPError:
            raise HTTPException(503, "Оркестратор Proxmox недоступен")
        if resp.status_code >= 400:
            try:
                detail = resp.json().get("detail")
            except ValueError:
                detail = None
            # 401 оркестратора — ошибка настройки центра, а не прав оператора
            status = 503 if resp.status_code in (401, 500, 502, 503) else resp.status_code
            raise HTTPException(status, detail if isinstance(detail, str) else "Ошибка оркестратора")
        return resp.json()
