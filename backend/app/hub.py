"""Рассылка событий подписчикам WebSocket (в пределах одного процесса)."""
from __future__ import annotations

import asyncio


class Hub:
    def __init__(self) -> None:
        self._subs: set[asyncio.Queue] = set()

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=500)
        self._subs.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subs.discard(q)

    def publish(self, payload: dict) -> None:
        for q in list(self._subs):
            if q.full():  # медленный клиент: теряем самое старое, а не блокируем приём телеметрии
                try:
                    q.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            q.put_nowait(payload)
