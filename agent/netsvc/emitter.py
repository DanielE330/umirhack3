"""Единая точка, куда ловушки сообщают о событиях: запись в буфер и сигнал отправщику."""
from __future__ import annotations

import asyncio
import time
import uuid

from .buffer import EventBuffer

FIELD_LIMITS = {"src_ip": 64, "proto": 16, "session_id": 64, "username": 128, "password": 256, "command": 4000}


class Emitter:
    def __init__(self, buffer: EventBuffer, capture_passwords: bool = True):
        self.buffer = buffer
        self.capture_passwords = capture_passwords
        self.wakeup = asyncio.Event()

    def emit(self, type: str, **fields) -> None:
        event = {"uid": uuid.uuid4().hex, "ts": time.time(), "type": type, "data": fields.pop("data", {})}
        for key, value in fields.items():
            if key in FIELD_LIMITS:
                value = str(value)[:FIELD_LIMITS[key]]
            event[key] = value
        if not self.capture_passwords and "password" in event:
            event["password"] = ""
        self.buffer.add(event)
        self.wakeup.set()
