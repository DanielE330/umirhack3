"""Low-ловушка: открытый порт с баннером. Фиксирует подключение и первые байты, которые прислал клиент."""
from __future__ import annotations

import asyncio
import random
import uuid

from ..emitter import Emitter

READ_TIMEOUT = 5.0


def printable(data: bytes, limit: int) -> str:
    return "".join(chr(b) if 32 <= b < 127 or b in (9, 10, 13) else "." for b in data[:limit])


class BannerTrap:
    def __init__(self, service: dict, config: dict, emitter: Emitter):
        self.service, self.config, self.emitter = service, config, emitter
        self.server: asyncio.AbstractServer | None = None

    async def start(self, host: str = "0.0.0.0") -> None:
        self.server = await asyncio.start_server(self._handle, host, self.service["port"])

    @property
    def port(self) -> int:
        return self.server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        if self.server:
            self.server.close()
            await self.server.wait_closed()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername") or ("", 0)
        sid = uuid.uuid4().hex[:16]
        base = dict(src_ip=peer[0], src_port=peer[1], dst_port=self.service["port"], proto="tcp", session_id=sid)
        self.emitter.emit("connect", **base)
        try:
            banner = self.service.get("banner", "")
            if banner:
                await asyncio.sleep(random.uniform(0.02, 0.15))  # живой сервис не отвечает мгновенно
                writer.write(banner.encode("utf-8", "replace") + b"\r\n")
                await writer.drain()
            logging = self.config.get("logging", {})
            limit = int(logging.get("max_payload_bytes", 512))
            data = await asyncio.wait_for(reader.read(max(limit, 1)), READ_TIMEOUT)
            if data and logging.get("capture_payload", True):
                self.emitter.emit("payload", **base, command=printable(data, limit),
                                  data={"hex": data[:limit].hex(), "bytes": len(data)})
        except (asyncio.TimeoutError, ConnectionError, OSError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass
