"""Клиент канала к центру: HTTPS, обычные заголовки браузера, случайный размер запросов (MASK-1, 2, 5)."""
from __future__ import annotations

import asyncio
import json
import random
import ssl
import string
import urllib.error
import urllib.request

VERSION = "1.0"
USER_AGENTS = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
)


class CenterError(Exception):
    pass


class CenterClient:
    def __init__(self, base_url: str, token: str, ca_file: str = "", insecure: bool = False, timeout: float = 15.0):
        self.base = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.ua = random.choice(USER_AGENTS)  # один UA на запуск: постоянный «браузер», а не шумящий каждый раз
        if insecure:  # только для демо со самоподписанным сертификатом; в проде задаётся HF_CA_FILE
            ctx = ssl.create_default_context()
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        else:
            ctx = ssl.create_default_context(cafile=ca_file or None)
        self.ctx = ctx

    def _request(self, method: str, path: str, body: dict | None = None) -> dict:
        data = None
        if body is not None:
            # Случайный «мусорный» хвост: размеры запросов не складываются в узнаваемый шаблон.
            body = {**body, "pad": "".join(random.choices(string.ascii_letters, k=random.randint(0, 400)))}
            data = json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data=data, method=method, headers={
            "Authorization": f"Bearer {self.token}", "User-Agent": self.ua, "Accept": "application/json",
            "Accept-Language": "en-US,en;q=0.9", **({"Content-Type": "application/json"} if data else {})})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as resp:
                return json.loads(resp.read() or b"{}")
        except (urllib.error.URLError, TimeoutError, ssl.SSLError, ValueError, OSError) as exc:
            raise CenterError(str(exc)) from exc

    async def manifest(self) -> dict:
        return await asyncio.to_thread(self._request, "GET", f"/assets/v1/manifest.json?v={VERSION}")

    async def send(self, events: list[dict]) -> dict:
        return await asyncio.to_thread(self._request, "POST", "/assets/v1/log", {"events": events})
