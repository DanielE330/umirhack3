"""Локальный буфер событий на SQLite: переживает обрыв связи и перезапуск агента (FR-A4)."""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path

MAX_ROWS = 100_000  # при переполнении выбрасываем самые старые, а не растём бесконечно


class EventBuffer:
    def __init__(self, path: str):
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._lock = threading.Lock()
        with self._lock:
            self._db.execute("CREATE TABLE IF NOT EXISTS q (seq INTEGER PRIMARY KEY AUTOINCREMENT, "
                             "uid TEXT UNIQUE, payload TEXT NOT NULL)")
            self._db.commit()

    def add(self, event: dict) -> None:
        with self._lock:
            self._db.execute("INSERT OR IGNORE INTO q(uid, payload) VALUES(?, ?)", (event["uid"], json.dumps(event)))
            self._db.execute("DELETE FROM q WHERE seq <= (SELECT MAX(seq) FROM q) - ?", (MAX_ROWS,))
            self._db.commit()

    def peek(self, limit: int) -> list[dict]:
        with self._lock:
            rows = self._db.execute("SELECT payload FROM q ORDER BY seq LIMIT ?", (limit,)).fetchall()
        return [json.loads(r[0]) for r in rows]

    def delete(self, uids: list[str]) -> None:
        if not uids:
            return
        with self._lock:
            self._db.executemany("DELETE FROM q WHERE uid = ?", [(u,) for u in uids])
            self._db.commit()

    def count(self) -> int:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM q").fetchone()[0]
