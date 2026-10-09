"""Medium-ловушка HTTP: правдоподобная админка с формой входа, 404 как у настоящего сервера, URL-приманки."""
from __future__ import annotations

import asyncio
import random
import uuid
from urllib.parse import parse_qs, unquote, urlsplit

from ..emitter import Emitter

MAX_HEADER = 16 * 1024
MAX_BODY = 8 * 1024
REQUEST_TIMEOUT = 10.0

LOGIN_PAGE = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Sign in - Admin Console</title>
<style>body{font-family:Arial,sans-serif;background:#f3f4f6;display:grid;place-items:center;height:100vh;margin:0}
form{background:#fff;padding:28px;border-radius:6px;box-shadow:0 1px 4px #0002;width:300px}
input{width:100%;padding:8px;margin:6px 0 12px;box-sizing:border-box}button{padding:8px 16px}
.e{color:#b91c1c;font-size:13px}</style></head>
<body><form method="post" action="/login"><h3>Admin Console</h3>{error}
<label>Username<input name="username"></label><label>Password<input type="password" name="password"></label>
<button>Sign in</button></form></body></html>"""

NOT_FOUND = """<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1>
<p>The requested URL was not found on this server.</p><hr><address>{server} Server</address></body></html>"""

STATUS = {200: "OK", 302: "Found", 404: "Not Found", 400: "Bad Request", 413: "Payload Too Large"}


class HttpTrap:
    def __init__(self, service: dict, config: dict, emitter: Emitter):
        self.service, self.config, self.emitter = service, config, emitter
        self.server: asyncio.AbstractServer | None = None
        self.server_header = service.get("banner") or "Apache/2.4.41 (Ubuntu)"
        decoys = config.get("decoys", {})
        self.users = {(u["username"], u["password"]) for u in decoys.get("users", [])}
        self.tokens = {t["path"]: t for t in decoys.get("honeytokens", []) if t.get("type") == "url"}

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
        base = dict(src_ip=peer[0], src_port=peer[1], dst_port=self.service["port"], proto="http", session_id=sid)
        try:
            for _ in range(20):  # keep-alive: несколько запросов в одном соединении, но не бесконечно
                request = await asyncio.wait_for(self._read_request(reader), REQUEST_TIMEOUT)
                if request is None:
                    break
                keep = await self._respond(request, writer, base)
                if not keep:
                    break
        except (asyncio.TimeoutError, ConnectionError, OSError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass

    async def _read_request(self, reader: asyncio.StreamReader):
        head = await reader.readuntil(b"\r\n\r\n") if not reader.at_eof() else b""
        if not head or len(head) > MAX_HEADER:
            return None
        lines = head.decode("latin-1").split("\r\n")
        parts = lines[0].split(" ")
        if len(parts) != 3:
            return {"bad": True, "raw": lines[0][:200]}
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        body = b""
        try:
            length = int(headers.get("content-length", "0") or 0)
        except ValueError:
            length = 0
        if length > MAX_BODY:
            return {"bad": True, "raw": lines[0][:200], "too_big": True}
        if length:
            body = await reader.readexactly(length)
        return {"method": parts[0][:16], "target": parts[1][:2000], "headers": headers, "body": body}

    async def _respond(self, req: dict, writer: asyncio.StreamWriter, base: dict) -> bool:
        await asyncio.sleep(random.uniform(0.01, 0.08))
        if req.get("bad"):
            self.emitter.emit("http_request", **base, command=req["raw"], data={"malformed": True})
            await self._send(writer, 413 if req.get("too_big") else 400, "Bad Request", close=True)
            return False

        split = urlsplit(req["target"])
        path = unquote(split.path)
        ua = req["headers"].get("user-agent", "")[:200]
        self.emitter.emit("http_request", **base, command=f"{req['method']} {req['target'][:500]}",
                          data={"user_agent": ua, "host": req["headers"].get("host", "")[:100]})

        if path in self.tokens:  # приманка-URL: любое обращение — компрометация сигнальных данных
            tok = self.tokens[path]
            self.emitter.emit("honeytoken", **base, command=path, data={"kind": "url"})
            await self._send(writer, 200, tok.get("content", ""), ctype="text/plain")
            return True

        if path == "/login" and req["method"] == "POST":
            form = parse_qs(req["body"].decode("utf-8", "replace"))
            user = (form.get("username") or [""])[0]
            password = (form.get("password") or [""])[0]
            self.emitter.emit("auth_attempt", **base, username=user, password=password)
            ok = (user, password) in self.users  # веб-форма пускает только по приманкам-учёткам
            if ok:
                await self._send(writer, 302, "", extra=["Location: /dashboard"])
            else:
                await asyncio.sleep(random.uniform(0.2, 0.6))  # «проверка пароля» занимает время
                await self._send(writer, 200, LOGIN_PAGE.replace("{error}", '<p class="e">Invalid username or password.</p>'))
            return True

        if path in ("/", "/login", "/admin", "/index.html"):
            await self._send(writer, 200, LOGIN_PAGE.replace("{error}", ""))
        elif path == "/dashboard":
            await self._send(writer, 200, "<html><body><h3>Dashboard</h3><p>Loading…</p></body></html>")
        else:
            await self._send(writer, 404, NOT_FOUND.replace("{server}", self.server_header.split(" ")[0]))
        return True

    async def _send(self, writer: asyncio.StreamWriter, status: int, body: str, ctype: str = "text/html; charset=UTF-8",
                    extra: list[str] | None = None, close: bool = False) -> None:
        payload = body.encode()
        head = [f"HTTP/1.1 {status} {STATUS.get(status, 'OK')}", f"Server: {self.server_header}",
                f"Content-Type: {ctype}", f"Content-Length: {len(payload)}",
                "Connection: close" if close else "Connection: keep-alive", *(extra or [])]
        writer.write(("\r\n".join(head) + "\r\n\r\n").encode() + payload)
        await writer.drain()
