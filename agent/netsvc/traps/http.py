"""Medium-ловушка HTTP: правдоподобная админка с формой входа, 404 как у настоящего сервера, URL-приманки."""
from __future__ import annotations

import asyncio
import random
import time
import uuid
from email.utils import formatdate
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

# Тексты ошибок один в один как у Apache 2.4 на Ubuntu (включая «Server at <хост> Port <порт>»)
ERROR_PAGE = """<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>{code} {reason}</title>
</head><body>
<h1>{title}</h1>
<p>{text}</p>
<hr>
<address>{server} Server at {host} Port {port}</address>
</body></html>
"""
ERRORS = {
    400: ("Bad Request", "Bad Request", "Your browser sent a request that this server could not understand.<br />"),
    403: ("Forbidden", "Forbidden", "You don't have permission to access this resource."),
    404: ("Not Found", "Not Found", "The requested URL was not found on this server."),
    405: ("Method Not Allowed", "Method Not Allowed", "The requested method {method} is not allowed for this URL."),
    408: ("Request Timeout", "Request Timeout", "Server timeout waiting for the HTTP request from the client."),
    413: ("Request Entity Too Large", "Request Entity Too Large", "The requested resource<br />{path}<br />\ndoes not allow request data with {method} requests, or the amount of data provided in\nthe request exceeds the capacity limit."),
    501: ("Not Implemented", "Not Implemented", "{method} not supported for current URL.<br />"),
}
STATUS = {200: "OK", 302: "Found", **{c: v[0] for c, v in ERRORS.items()}}
KNOWN_METHODS = {"GET", "HEAD", "POST", "OPTIONS", "PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}
# Пути, которые на настоящем Apache/Ubuntu отвечают 403, а не 404
FORBIDDEN = ("/server-status", "/server-info", "/.htaccess", "/.htpasswd", "/icons/.htaccess")

DEFAULT_HONEYTOKENS = {
    "/.env": {
        "type": "url",
        "path": "/.env",
        "content": (
            "APP_NAME=AdminConsole\nAPP_ENV=production\nAPP_KEY=base64:4s8V7xN3B9w8Z1m4K6t8Q2e4L7P9R1s3=\n"
            "APP_DEBUG=false\nDB_CONNECTION=mysql\nDB_HOST=127.0.0.1\nDB_PORT=3306\nDB_DATABASE=company_prod\n"
            "DB_USERNAME=portal_admin\nDB_PASSWORD=SuperSecretProdPass2026!\n"
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        ),
    },
    "/.git/config": {
        "type": "url",
        "path": "/.git/config",
        "content": (
            "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n\tlogallrefupdates = true\n"
            "[remote \"origin\"]\n\turl = https://token:ghp_faketoken9812376@github.com/corp-internal/admin-api.git\n"
            "\tfetch = +refs/heads/*:refs/remotes/origin/*\n[branch \"main\"]\n\tremote = origin\n\tmerge = refs/heads/main\n"
        ),
    },
    "/robots.txt": {
        "type": "url",
        "path": "/robots.txt",
        "content": "User-agent: *\nDisallow: /admin\nDisallow: /login\nDisallow: /dashboard\nDisallow: /.env\nDisallow: /backup.sql\n",
    },
}

ATTACK_PROBES = (
    "../", "..\\", "/etc/passwd", "/etc/shadow", "/proc/",
    "cmd=", "exec=", "eval=", "system=", "shell=", "passthru=",
    "union select", "' or 1=1", "union%20select",
    "<script", "<?php", "phpinfo()", "base64_decode",
)


class HttpTrap:
    def __init__(self, service: dict, config: dict, emitter: Emitter):
        self.service, self.config, self.emitter = service, config, emitter
        self.server: asyncio.AbstractServer | None = None
        self.server_header = service.get("banner") or "Apache/2.4.41 (Ubuntu)"
        decoys = config.get("decoys", {})
        self.users = {(u["username"], u["password"]) for u in decoys.get("users", [])}
        user_tokens = {t["path"]: t for t in decoys.get("honeytokens", []) if t.get("type") == "url"}
        self.tokens = {**DEFAULT_HONEYTOKENS, **user_tokens}

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
            await self._error(writer, 413 if req.get("too_big") else 400, req, close=True)
            return False

        split = urlsplit(req["target"])
        path = unquote(split.path)
        ua = req["headers"].get("user-agent", "")[:200]
        self.emitter.emit("http_request", **base, command=f"{req['method']} {req['target'][:500]}",
                          data={"user_agent": ua, "host": req["headers"].get("host", "")[:100]})

        lower_target = req["target"].lower()
        if any(probe in lower_target for probe in ATTACK_PROBES):
            self.emitter.emit("payload", **base, command=f"{req['method']} {req['target'][:500]}",
                              data={"kind": "web-attack-probe", "path": path, "user_agent": ua})

        method = req["method"].upper()
        if method not in KNOWN_METHODS:
            await self._error(writer, 501, req)
            return True

        if path in self.tokens:  # приманка-URL: любое обращение — компрометация сигнальных данных
            tok = self.tokens[path]
            if path != "/robots.txt":  # robots.txt читают и безобидные краулеры — это не компрометация
                self.emitter.emit("honeytoken", **base, command=path, data={"kind": "url"})
            await self._send(writer, 200, tok.get("content", ""), ctype="text/plain", req=req)
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

        if method == "OPTIONS":
            await self._send(writer, 200, "", extra=["Allow: OPTIONS,HEAD,GET,POST"], req=req)
        elif path in ("/", "/login", "/admin", "/index.html"):
            if method in ("GET", "HEAD"):
                await self._send(writer, 200, LOGIN_PAGE.replace("{error}", ""), req=req)
            else:
                await self._error(writer, 405, req)
        elif path == "/dashboard":
            await self._send(writer, 200, "<html><body><h3>Dashboard</h3><p>Loading…</p></body></html>", req=req)
        elif path.rstrip("/") in FORBIDDEN or path.startswith("/.ht"):
            await self._error(writer, 403, req)
        else:
            await self._error(writer, 404, req)
        return True

    async def _error(self, writer: asyncio.StreamWriter, status: int, req: dict, close: bool = False) -> None:
        reason, title, text = ERRORS[status]
        host = (req.get("headers", {}).get("host") or self.service.get("host") or "localhost").split(":")[0][:100]
        # Страницу ошибки строит Apache по заголовку Host — так же делаем и мы
        body = ERROR_PAGE.format(code=status, reason=reason, title=title, host=host, port=self.service["port"],
                                 server=self.server_header,
                                 text=text.format(method=req.get("method", ""), path=urlsplit(req.get("target", "/")).path[:200]))
        await self._send(writer, status, body, close=close, req=req)

    async def _send(self, writer: asyncio.StreamWriter, status: int, body: str, ctype: str = "text/html; charset=UTF-8",
                    extra: list[str] | None = None, close: bool = False, req: dict | None = None) -> None:
        payload = body.encode()
        head_only = bool(req) and req.get("method", "").upper() == "HEAD"
        head = [f"HTTP/1.1 {status} {STATUS.get(status, 'OK')}", f"Date: {formatdate(usegmt=True)}",
                f"Server: {self.server_header}", *(extra or []),
                *(["Vary: Accept-Encoding"] if status == 200 and ctype.startswith("text/html") else []),
                f"Content-Length: {len(payload)}", "Connection: close" if close else "Keep-Alive: timeout=5, max=100",
                *([] if close else ["Connection: Keep-Alive"]), f"Content-Type: {ctype}"]
        writer.write(("\r\n".join(head) + "\r\n\r\n").encode() + (b"" if head_only else payload))
        await writer.drain()
