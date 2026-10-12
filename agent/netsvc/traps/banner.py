"""Low-ловушка: открытый порт с баннером и интерактивным протоколом (TCP, Redis, FTP).
Фиксирует подключение, полезную нагрузку, попытки авторизации и держит интерактивную сессию."""
from __future__ import annotations

import asyncio
import random
import uuid

from ..emitter import Emitter

READ_TIMEOUT = 5.0
MAX_TURNS = 20


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
        port = self.service.get("port", 0)
        base = dict(src_ip=peer[0], src_port=peer[1], dst_port=port, proto="tcp", session_id=sid)
        self.emitter.emit("connect", **base)

        logging_cfg = self.config.get("logging", {})
        limit = int(logging_cfg.get("max_payload_bytes", 512))
        capture_payload = logging_cfg.get("capture_payload", True)
        banner = self.service.get("banner", "")

        is_redis = port == 6379 or "redis" in banner.lower()
        is_ftp = port == 21 or banner.startswith("220")
        ftp_user = ""

        try:
            if banner and not is_redis:
                await asyncio.sleep(random.uniform(0.02, 0.12))
                writer.write(banner.encode("utf-8", "replace") + b"\r\n")
                await writer.drain()

            for _ in range(MAX_TURNS):
                try:
                    data = await asyncio.wait_for(reader.read(max(limit, 1)), READ_TIMEOUT)
                except asyncio.TimeoutError:
                    break
                if not data:
                    break

                text = printable(data, limit)
                if capture_payload:
                    self.emitter.emit("payload", **base, command=text,
                                      data={"hex": data[:limit].hex(), "bytes": len(data)})

                line = text.strip()
                upper = line.upper()

                # Реалистичная сетевая задержка ответа сервиса (MASK-5, MASK-6)
                await asyncio.sleep(random.uniform(0.01, 0.04))

                if is_redis or upper.startswith(("PING", "INFO", "AUTH", "SET ", "GET ", "CONFIG")):
                    if upper.startswith("PING"):
                        writer.write(b"+PONG\r\n")
                    elif upper.startswith("INFO"):
                        resp = (b"$115\r\n# Server\r\nredis_version:6.0.9\r\nos:Linux 5.4.0-150-generic x86_64\r\n"
                                b"tcp_port:6379\r\nuptime_in_seconds:145020\r\nconnected_clients:1\r\n\r\n")
                        writer.write(resp)
                    elif upper.startswith("AUTH"):
                        parts = line.split()
                        pwd = parts[-1] if len(parts) >= 2 else ""
                        usr = parts[1] if len(parts) >= 3 else "default"
                        self.emitter.emit("auth_attempt", **base, username=usr, password=pwd)
                        writer.write(b"+OK\r\n")
                    elif upper.startswith("CONFIG"):
                        writer.write(b"-ERR Unsupported CONFIG parameter\r\n")
                    elif upper.startswith("QUIT"):
                        writer.write(b"+OK\r\n")
                        await writer.drain()
                        break
                    elif upper.startswith(("SET ", "GET ")):
                        writer.write(b"+OK\r\n")
                    else:
                        cmd_name = line.split()[0] if line.split() else "unknown"
                        writer.write(f"-ERR unknown command '{cmd_name}'\r\n".encode())
                    await writer.drain()

                elif is_ftp or upper.startswith(("USER ", "PASS ", "SYST", "QUIT")):
                    if upper.startswith("USER "):
                        ftp_user = line.split(" ", 1)[1] if " " in line else "anonymous"
                        writer.write(f"331 Password required for {ftp_user}.\r\n".encode())
                    elif upper.startswith("PASS "):
                        ftp_pass = line.split(" ", 1)[1] if " " in line else ""
                        self.emitter.emit("auth_attempt", **base, username=ftp_user or "anonymous", password=ftp_pass)
                        writer.write(b"530 Login incorrect.\r\n")
                    elif upper.startswith("SYST"):
                        writer.write(b"215 UNIX Type: L8\r\n")
                    elif upper.startswith("QUIT"):
                        writer.write(b"221 Goodbye.\r\n")
                        await writer.drain()
                        break
                    else:
                        cmd_name = line.split()[0] if line.split() else "unknown"
                        writer.write(f"500 Unknown command '{cmd_name}'.\r\n".encode())
                    await writer.drain()

                elif upper.startswith(("GET ", "POST ", "HEAD ")):
                    writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    await writer.drain()
                    break

        except (asyncio.TimeoutError, ConnectionError, OSError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass
