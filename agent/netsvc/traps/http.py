"""Medium-ловушка HTTP / OpenSource Web Honeypot.
Эмулирует уязвимый корпоративный портал и веб-приложения:
- XSS: отражённый и хранимый межсайтовый скриптинг (отражение в curl / HTML, фиксация пейлоада)
- SQL-инъекции (SQLi): Error-based (ошибки MySQL), Union-based (утечка honeytoken-дампа), Auth Bypass
- LFI / Path Traversal: чтение системных файлов (/etc/passwd, /etc/shadow, /.env)
- Command Injection (RCE): утилита диагностики (/tools/ping) с симуляцией выполнения shell-команд
- WordPress / Wordpot: эмуляция /wp-login.php, xmlrpc.php (pingback, multicall, брутфорс)
- phpMyAdmin: эмуляция консоли входа /phpmyadmin/ и /pma/
- Log4Shell (CVE-2021-44228): перехват JNDI/LDAP инъекций в заголовках и теле запроса
"""
from __future__ import annotations

import asyncio
import html
import json
import random
import re
import time
import uuid
from email.utils import formatdate
from urllib.parse import parse_qs, unquote, urlsplit

from ..emitter import Emitter

MAX_HEADER = 16 * 1024
MAX_BODY = 32 * 1024
REQUEST_TIMEOUT = 10.0

# ────────────────── Регулярные выражения детекции веб-атак ──────────────────

# XSS (Cross-Site Scripting)
XSS_RX = re.compile(
    r"(?i)(?:<script\b[^>]*>|javascript:|onerror\s*=|onload\s*=|onclick\s*=|onmouseover\s*=|"
    r"eval\s*\(|alert\s*\(|prompt\s*\(|confirm\s*\(|<img\b[^>]*onerror|<svg\b[^>]*onload|"
    r"<iframe\b|<body\b[^>]*onload|document\.cookie|document\.location|String\.fromCharCode)"
)

# SQL-инъекции (SQLi)
SQLI_RX = re.compile(
    r"(?i)(?:\bunion\s+(?:all\s+)?select\b|'\s*or\s+'?1'?\s*=\s*'?1|'\s*or\s+1\s*=\s*1|"
    r"\bor\s+1=1|\bselect\b.+\bfrom\b.+\bwhere\b|\bsleep\s*\(\s*\d+\s*\)|\bbenchmark\s*\(\s*\d+|"
    r"\bextractvalue\s*\(|\bupdatexml\s*\(|;\s*drop\s+(?:table|database)\b|;\s*insert\s+into\b|"
    r"information_schema|load_file\s*\(|into\s+(?:dumpfile|outfile)\b|version\s*\(\s*\)|"
    r"database\s*\(\s*\)|user\s*\(\s*\)|\bgroup\s+by\b.+\bhaving\b|\border\s+by\s+\d+|--\s*$|#\s*$)"
)

# LFI / Path Traversal
LFI_RX = re.compile(
    r"(?:\.\.[/\\]|etc/(?:passwd|shadow|hosts|issue)|proc/self/|win\.ini|boot\.ini|"
    r"php://(?:filter|input)|file://|data://)"
)

# Command Injection (RCE)
RCE_RX = re.compile(
    r"(?:[;&|`$]\s*(?:cat|id|whoami|uname|ls|pwd|curl|wget|bash|sh|rm|kill|ping|nc|python)\b|"
    r"\$\([^)]+\)|`[^`]+`)"
)

# Log4Shell (CVE-2021-44228)
LOG4J_RX = re.compile(r"\$\{jndi:(?:ldap|rmi|dns|nis|iiop|corba)://([^}\s]+)\}")

# PHP Webshell / Injections
PHP_RX = re.compile(
    r"(?i)(?:<\?php|eval\s*\(\s*(?:base64_decode|\$_POST|\$_GET)|system\s*\(\s*\$_|"
    r"passthru\s*\(|shell_exec\s*\()"
)

ATTACK_PROBES = (
    "../", "..\\", "/etc/passwd", "/etc/shadow", "/proc/",
    "cmd=", "exec=", "eval=", "system=", "shell=", "passthru=",
    "union select", "' or 1=1", "union%20select",
    "<script", "<?php", "phpinfo()", "base64_decode",
)

# ────────────────── HTML шаблоны и ответы ──────────────────

PORTAL_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Enterprise Service Portal - Corporate Network</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 40px; }
.card { background: #1e293b; border-radius: 8px; padding: 24px; max-width: 800px; margin: 0 auto; box-shadow: 0 4px 6px -1px #0004; }
h1 { color: #38bdf8; margin-top: 0; }
.search-box { margin: 24px 0; }
input[type="text"] { width: 70%; padding: 10px; border-radius: 4px; border: 1px solid #475569; background: #0f172a; color: #fff; }
button { padding: 10px 20px; background: #0284c7; border: none; color: #fff; border-radius: 4px; cursor: pointer; }
.links { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-top: 30px; }
.link-btn { background: #334155; padding: 14px; border-radius: 6px; text-decoration: none; color: #cbd5e1; display: block; border-left: 4px solid #38bdf8; }
.link-btn:hover { background: #475569; }
footer { margin-top: 30px; font-size: 12px; color: #64748b; text-align: center; }
</style>
</head>
<body>
<div class="card">
  <h1>🏢 Internal Service Portal</h1>
  <p>Authorized access only. All activities are monitored and logged.</p>
  
  <div class="search-box">
    <form method="get" action="/search">
      <input type="text" name="q" placeholder="Search knowledge base, assets, users…">
      <button type="submit">Search</button>
    </form>
  </div>

  <div class="links">
    <a href="/login" class="link-btn"><b>🔐 Admin Console</b><br><small>Central management authentication</small></a>
    <a href="/tools/ping" class="link-btn"><b>🌐 Network Diagnostics</b><br><small>Ping & traceroute utilities</small></a>
    <a href="/api/products" class="link-btn"><b>📦 Catalog & Assets API</b><br><small>REST API /api/products?id=1</small></a>
    <a href="/download?file=readme.txt" class="link-btn"><b>📄 Document Storage</b><br><small>Public policy and assets</small></a>
  </div>
  
  <footer>Corporate IT Infrastructure · Apache/2.4.52 (Ubuntu)</footer>
</div>
</body>
</html>
"""

LOGIN_PAGE = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Sign in - Admin Console</title>
<style>body{font-family:Arial,sans-serif;background:#f3f4f6;display:grid;place-items:center;height:100vh;margin:0}
form{background:#fff;padding:28px;border-radius:6px;box-shadow:0 1px 4px #0002;width:300px}
input{width:100%;padding:8px;margin:6px 0 12px;box-sizing:border-box}button{padding:8px 16px}
.e{color:#b91c1c;font-size:13px}</style></head>
<body><form method="post" action="/login"><h3>Admin Console</h3>{error}
<label>Username<input name="username"></label><label>Password<input type="password" name="password"></label>
<button>Sign in</button></form></body></html>"""

WP_LOGIN_PAGE = """<!DOCTYPE html>
<html lang="en-US">
<head>
<meta charset="UTF-8">
<title>Log In &lsaquo; Corporate Blog &#8212; WordPress</title>
<style>
body { background: #f0f0f1; color: #3c434a; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif; height: 100vh; display: grid; place-items: center; margin: 0; }
.login { width: 320px; padding: 24px; background: #fff; border: 1px solid #c3c4c7; box-shadow: 0 1px 3px rgba(0,0,0,.04); }
.login h1 { text-align: center; margin-bottom: 24px; }
.login label { font-size: 14px; line-height: 1.5; color: #3c434a; }
.login input[type="text"], .login input[type="password"] { width: 100%; padding: 6px 10px; margin: 6px 0 16px; border: 1px solid #8c8f94; border-radius: 4px; box-sizing: border-box; }
.login .button-primary { background: #2271b1; border-color: #2271b1; color: #fff; padding: 6px 14px; border-radius: 4px; cursor: pointer; float: right; font-weight: 600; }
.login-error { background: #fff; border-left: 4px solid #d63638; padding: 12px; margin-bottom: 20px; box-shadow: 0 1px 1px 0 rgba(0,0,0,.04); font-size: 13px; }
</style>
</head>
<body class="login">
<div>
  <h1>WordPress</h1>
  {error}
  <form name="loginform" id="loginform" action="/wp-login.php" method="post" class="login">
    <p><label for="user_login">Username or Email Address</label><input type="text" name="log" id="user_login" class="input" value="" size="20"></p>
    <p><label for="user_pass">Password</label><input type="password" name="pwd" id="user_pass" class="input" value="" size="20"></p>
    <p class="submit"><input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Log In"></p>
  </form>
</div>
</body>
</html>
"""

PMA_LOGIN_PAGE = """<!DOCTYPE HTML>
<html lang="en" dir="ltr">
<head>
<meta charset="utf-8">
<title>phpMyAdmin 5.2.1</title>
<style>
body { background: #f5f5f5; font-family: sans-serif; display: grid; place-items: center; height: 100vh; margin: 0; }
.pma-box { background: #fff; border: 1px solid #ddd; padding: 30px; width: 340px; box-shadow: 0 2px 4px #0001; }
h2 { color: #f89406; margin-top: 0; }
input { width: 100%; padding: 8px; margin: 8px 0 16px; box-sizing: border-box; border: 1px solid #ccc; }
button { background: #007bff; color: #fff; border: none; padding: 8px 16px; border-radius: 3px; cursor: pointer; }
.err { background: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; padding: 10px; margin-bottom: 15px; font-size: 13px; }
</style>
</head>
<body>
<div class="pma-box">
  <h2>phpMyAdmin</h2>
  {error}
  <form method="post" action="/phpmyadmin/index.php">
    <label>Username:<input type="text" name="pma_username"></label>
    <label>Password:<input type="password" name="pma_password"></label>
    <button type="submit">Log in</button>
  </form>
</div>
</body>
</html>
"""

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
    500: ("Internal Server Error", "Internal Server Error", "The server encountered an internal error or misconfiguration and was unable to complete your request."),
    501: ("Not Implemented", "Not Implemented", "{method} not supported for current URL.<br />"),
}
STATUS = {200: "OK", 302: "Found", **{c: v[0] for c, v in ERRORS.items()}}
KNOWN_METHODS = {"GET", "HEAD", "POST", "OPTIONS", "PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}
FORBIDDEN = ("/server-status", "/server-info", "/.htaccess", "/.htpasswd", "/icons/.htaccess")

FAKE_PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
admin:x:1000:1000:admin:/home/admin:/bin/bash
deploy:x:1001:1001:deployer:/home/deploy:/bin/bash
"""

FAKE_SHADOW = """root:$6$rounds=656000$p8L3n2F8d$J7V3vK0uQw2xY1eP5QGefi2DMPTfTL5SLmv7DivfNa:19700:0:99999:7:::
daemon:*:19650:0:99999:7:::
bin:*:19650:0:99999:7:::
www-data:*:19650:0:99999:7:::
admin:$6$rounds=656000$q1W2e3R4t$e8ZzG7kK.9W2xY3q1P0uQw2xY1eP5QGefi2DMPTfTL:19700:0:99999:7:::
deploy:$6$rounds=656000$a9S8d7F6g$3LmN8vR1xQ2yZ0uQw2xY1eP5QGefi2DMPTfTL5SL:19700:0:99999:7:::
"""

DEFAULT_HONEYTOKENS = {
    "/.env": {
        "type": "url",
        "path": "/.env",
        "content": (
            "APP_NAME=EnterprisePortal\nAPP_ENV=production\nAPP_KEY=base64:4s8V7xN3B9w8Z1m4K6t8Q2e4L7P9R1s3=\n"
            "APP_DEBUG=false\nDB_CONNECTION=mysql\nDB_HOST=127.0.0.1\nDB_PORT=3306\nDB_DATABASE=company_prod\n"
            "DB_USERNAME=portal_admin\nDB_PASSWORD=SuperSecretProdPass2026!\n"
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
            "JWT_SECRET=c8d4e9f1a2b3c4d5e6f7a8b9c0d1e2f3\n"
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
        "content": "User-agent: *\nDisallow: /admin\nDisallow: /login\nDisallow: /dashboard\nDisallow: /.env\nDisallow: /wp-admin/\nDisallow: /phpmyadmin/\nDisallow: /backup.sql\n",
    },
}


class HttpTrap:
    """
    OpenSource & Medium-Interaction Web Honeypot.
    Поддерживает:
    - XSS: отражённый скриптинг в поиске /search?q=...
    - SQLi: Error-based (ошибки MySQL) и Union-based (утечки таблиц) в /search и /api/products
    - LFI: чтение локальных файлов через /download?file=... и /view?page=...
    - RCE: внедрение команд через /tools/ping?host=...
    - Wordpot: эмуляция WordPress (/wp-login.php, xmlrpc.php)
    - phpMyAdmin: эмуляция консоли входа (/phpmyadmin/, /pma/)
    - Log4Shell: перехват JNDI/LDAP инъекций в заголовках
    """

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
            for _ in range(25):  # keep-alive: до 25 запросов в соединении
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
        await asyncio.sleep(random.uniform(0.01, 0.05))
        if req.get("bad"):
            self.emitter.emit("http_request", **base, command=req.get("raw", ""), data={"malformed": True})
            await self._error(writer, 413 if req.get("too_big") else 400, req, close=True)
            return False

        split = urlsplit(req["target"])
        path = unquote(split.path)
        qs = parse_qs(split.query)
        ua = req["headers"].get("user-agent", "")[:250]
        raw_target = req["target"]
        decoded_target = unquote(raw_target)
        method = req["method"].upper()

        # Базовая фиксация HTTP запроса
        self.emitter.emit("http_request", **base, command=f"{req['method']} {req['target'][:500]}",
                          data={"user_agent": ua, "host": req["headers"].get("host", "")[:100]})

        lower_target = req["target"].lower()
        if any(probe in lower_target for probe in ATTACK_PROBES) and not (path in ("/search", "/tools/ping") or path.startswith("/api/products") or path.startswith("/download")):
            self.emitter.emit("payload", **base, command=f"{req['method']} {req['target'][:500]}",
                              data={"kind": "web-attack-probe", "path": path, "user_agent": ua})

        if method not in KNOWN_METHODS:
            await self._error(writer, 501, req)
            return True

        # ── 1. Инспекция Log4Shell (CVE-2021-44228) в заголовках и таргете ──
        for h_name, h_val in req["headers"].items():
            m_log4j = LOG4J_RX.search(h_val)
            if m_log4j:
                c2 = m_log4j.group(1)
                self.emitter.emit("payload", **base, command=f"{method} {path} [Log4j Header: {h_name}]",
                                  data={"kind": "web-attack-probe", "category": "log4shell", "threat_score": 95,
                                        "c2": c2, "header": h_name, "payload": h_val[:200]})
                resp = json.dumps({"status": "error", "error": f"Failed to perform JNDI lookup: javax.naming.NamingException for {c2}"})
                await self._send(writer, 500, resp, ctype="application/json", req=req)
                return True

        m_log4j_target = LOG4J_RX.search(decoded_target)
        if m_log4j_target:
            c2 = m_log4j_target.group(1)
            self.emitter.emit("payload", **base, command=f"{method} {path} [Log4j URI]",
                              data={"kind": "web-attack-probe", "category": "log4shell", "threat_score": 95,
                                    "c2": c2, "payload": decoded_target[:200]})
            resp = json.dumps({"status": "error", "error": f"Failed to perform JNDI lookup for {c2}"})
            await self._send(writer, 500, resp, ctype="application/json", req=req)
            return True

        # ── 2. Honeytokens (/.env, /.git/config, /robots.txt, etc.) ──
        if path in self.tokens:
            tok = self.tokens[path]
            if path != "/robots.txt":
                self.emitter.emit("honeytoken", **base, command=path, data={"kind": "url", "threat_score": 92})
            await self._send(writer, 200, tok.get("content", ""), ctype="text/plain", req=req)
            return True

        # ── 3. Поиск /search (XSS & SQLi Reflected) ──
        if path == "/search":
            q = (qs.get("q") or [""])[0]
            if not q and method == "POST":
                form = parse_qs(req["body"].decode("utf-8", "replace"))
                q = (form.get("q") or [""])[0]

            # XSS инъекция
            if q and XSS_RX.search(q):
                self.emitter.emit("payload", **base, command=f"{method} {raw_target[:400]}",
                                  data={"kind": "web-attack-probe", "category": "xss", "threat_score": 85,
                                        "attack_type": "xss", "param": "q", "payload": q[:300]})
                # Отражаем XSS сырым в HTML (Reflected XSS), чтобы в curl и браузере он сработал
                body = f"""<!DOCTYPE html><html><head><title>Search Results</title></head>
<body>
<h1>Search Results</h1>
<p>Results for query: <span id="query-result">{q}</span> (0 items found)</p>
<hr>
<p><a href="/">Return to Portal</a></p>
</body></html>"""
                await self._send(writer, 200, body, req=req)
                return True

            # SQLi инъекция
            if q and SQLI_RX.search(q):
                self.emitter.emit("payload", **base, command=f"{method} {raw_target[:400]}",
                                  data={"kind": "web-attack-probe", "category": "sqli", "threat_score": 92,
                                        "attack_type": "sqli", "param": "q", "payload": q[:300]})
                if "union" in q.lower():
                    # Union-based дамп honeytoken таблицы
                    body = """<!DOCTYPE html><html><head><title>Database Query Dump</title></head><body>
<h2>Query Results (Extracted Data)</h2>
<table border="1" cellpadding="6" style="border-collapse:collapse; background:#f8fafc; font-family:monospace;">
<tr style="background:#e2e8f0;"><th>ID</th><th>Username</th><th>Email</th><th>Password_Hash</th></tr>
<tr><td>1</td><td>admin</td><td>admin@corp.internal</td><td>$2y$10$e8ZzG7kK.9W2xY3q1P0uQw2xY1eP5QGefi2DMPTfTL</td></tr>
<tr><td>2</td><td>db_backup</td><td>backup@corp.internal</td><td>$2y$10$3LmN8vR1xQ2yZ0uQw2xY1eP5QGefi2DMPTfTL5SL</td></tr>
</table>
</body></html>"""
                    await self._send(writer, 200, body, req=req)
                else:
                    # Error-based симуляция ошибки MySQL
                    body = f"""<!DOCTYPE html><html><head><title>500 Internal Server Error</title></head><body>
<h1>Database Error</h1>
<p><b>SQLSTATE[42000]: Syntax error or access violation:</b> 1064 You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '{html.escape(q[:40])}' at line 1</p>
<hr><address>Apache/2.4.52 (Ubuntu) Server at localhost Port 8080</address>
</body></html>"""
                    await self._send(writer, 500, body, req=req)
                return True

            # Обычный безопасный поиск
            body = f"""<!DOCTYPE html><html><head><title>Search</title></head><body>
<h2>Search Results</h2>
<p>Found 0 records matching: <i>{html.escape(q)}</i></p>
<p><a href="/">Back</a></p></body></html>"""
            await self._send(writer, 200, body, req=req)
            return True

        # ── 4. REST API /api/products (SQLi) ──
        if path.startswith("/api/products") or path.startswith("/api/v1/user") or path.startswith("/api/item"):
            item_id = (qs.get("id") or [""])[0]
            if item_id and ("'" in item_id or '"' in item_id or SQLI_RX.search(item_id)):
                self.emitter.emit("payload", **base, command=f"{method} {raw_target[:400]}",
                                  data={"kind": "web-attack-probe", "category": "sqli", "threat_score": 92,
                                        "attack_type": "sqli", "param": "id", "payload": item_id[:300]})
                if "union" in item_id.lower():
                    res = json.dumps({
                        "status": "success",
                        "data": [
                            {"id": 1, "username": "admin", "role": "superuser", "api_token": "hf_tok_8941276384"},
                            {"id": 2, "username": "portal_svc", "role": "operator", "api_token": "hf_tok_1102938475"}
                        ]
                    }, indent=2)
                    await self._send(writer, 200, res, ctype="application/json", req=req)
                else:
                    res = json.dumps({
                        "error": "SQLSTATE[42000]: Syntax error or access violation: 1064 You have an error in your SQL syntax near '\'' at line 1",
                        "query": f"SELECT * FROM products WHERE id = {item_id}"
                    })
                    await self._send(writer, 500, res, ctype="application/json", req=req)
                return True
            # Обычный ответ API
            res = json.dumps({"id": item_id or 1, "name": "Enterprise Workstation", "price": 1299.99, "status": "active"})
            await self._send(writer, 200, res, ctype="application/json", req=req)
            return True

        # ── 5. Сетевая утилита /tools/ping (Command Injection / RCE) ──
        if path.startswith("/tools/ping") or path.startswith("/api/ping"):
            host_val = (qs.get("host") or qs.get("ip") or [""])[0]
            if not host_val and method == "POST":
                form = parse_qs(req["body"].decode("utf-8", "replace"))
                host_val = (form.get("host") or form.get("ip") or [""])[0]

            if host_val and RCE_RX.search(host_val):
                self.emitter.emit("payload", **base, command=f"{method} {raw_target[:400]}",
                                  data={"kind": "web-attack-probe", "category": "rce", "threat_score": 95,
                                        "attack_type": "rce", "param": "host", "injected_command": host_val[:300]})
                # Правдоподобный вывод Linux bash
                cmd_lower = host_val.lower()
                if "id" in cmd_lower:
                    out = "uid=33(www-data) gid=33(www-data) groups=33(www-data)"
                elif "whoami" in cmd_lower:
                    out = "www-data"
                elif "uname" in cmd_lower:
                    out = "Linux web-prod-01 5.15.0-101-generic #111-Ubuntu SMP Thu Aug 15 14:02:11 UTC 2024 x86_64 x86_64 GNU/Linux"
                elif "passwd" in cmd_lower:
                    out = FAKE_PASSWD.strip()
                elif "ls" in cmd_lower:
                    out = "index.php  config.php  login.php  robots.txt  tools/  download/  assets/"
                else:
                    out = f"[sh: {host_val[:30]}: command executed with return code 0]"

                resp = f"PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.\n64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.035 ms\n\n--- 127.0.0.1 ping statistics ---\n1 packets transmitted, 1 received, 0% packet loss\n{out}\n"
                await self._send(writer, 200, resp, ctype="text/plain", req=req)
                return True

            # Обычный пинг
            resp = f"PING {host_val or '127.0.0.1'} 56(84) bytes of data.\n64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.032 ms\n"
            await self._send(writer, 200, resp, ctype="text/plain", req=req)
            return True

        # ── 6. Скачивание /download или /view (LFI / Path Traversal) ──
        if path.startswith("/download") or path.startswith("/view") or path.startswith("/include"):
            file_val = (qs.get("file") or qs.get("page") or qs.get("path") or [""])[0]
            if file_val and LFI_RX.search(file_val):
                self.emitter.emit("honeytoken", **base, command=f"{method} {path}?file={file_val[:100]}",
                                  data={"kind": "web-attack-probe", "category": "lfi", "threat_score": 88,
                                        "attack_type": "lfi", "path": file_val[:200]})
                if "shadow" in file_val.lower():
                    await self._send(writer, 200, FAKE_SHADOW, ctype="text/plain", req=req)
                elif "env" in file_val.lower():
                    await self._send(writer, 200, DEFAULT_HONEYTOKENS["/.env"]["content"], ctype="text/plain", req=req)
                else:
                    await self._send(writer, 200, FAKE_PASSWD, ctype="text/plain", req=req)
                return True

            await self._send(writer, 200, "Corporate Policy Document (v2.4)\nStatus: Approved\nDepartment: Security Operations", ctype="text/plain", req=req)
            return True

        # ── 7. WordPress / Wordpot Эмуляция ──
        if path == "/wp-login.php":
            if method == "POST":
                form = parse_qs(req["body"].decode("utf-8", "replace"))
                log_u = (form.get("log") or [""])[0]
                pwd_u = (form.get("pwd") or [""])[0]
                self.emitter.emit("auth_attempt", **base, username=log_u, password=pwd_u)
                self.emitter.emit("payload", **base, command=f"POST /wp-login.php user={log_u[:40]}",
                                  data={"kind": "web-attack-probe", "category": "wordpot", "threat_score": 75,
                                        "app": "wordpress", "username": log_u, "password": pwd_u})
                err_box = f'<div class="login-error"><strong>Error</strong>: The password you entered for the username <b>{html.escape(log_u)}</b> is incorrect.</div>'
                await self._send(writer, 200, WP_LOGIN_PAGE.replace("{error}", err_box), req=req)
            else:
                await self._send(writer, 200, WP_LOGIN_PAGE.replace("{error}", ""), req=req)
            return True

        if path == "/xmlrpc.php":
            body_text = req["body"].decode("utf-8", "replace")
            self.emitter.emit("payload", **base, command="POST /xmlrpc.php",
                              data={"kind": "web-attack-probe", "category": "wordpot", "threat_score": 78,
                                    "app": "wordpress", "xmlrpc_method": "call"})
            if "system.listMethods" in body_text:
                xml_resp = """<?xml version="1.0" encoding="UTF-8"?>
<methodResponse><params><param><value><array><data>
<value><string>system.multicall</string></value>
<value><string>system.listMethods</string></value>
<value><string>pingback.ping</string></value>
<value><string>wp.getUsersBlogs</string></value>
<value><string>wp.newPost</string></value>
</data></array></value></param></params></methodResponse>"""
            else:
                xml_resp = """<?xml version="1.0" encoding="UTF-8"?>
<methodResponse><params><param><value><boolean>1</boolean></value></param></params></methodResponse>"""
            await self._send(writer, 200, xml_resp, ctype="text/xml; charset=UTF-8", req=req)
            return True

        if path.startswith("/wp-admin"):
            await self._send(writer, 302, "", extra=["Location: /wp-login.php?redirect_to=%2Fwp-admin%2F"], req=req)
            return True

        # ── 8. phpMyAdmin Эмуляция ──
        if path.rstrip("/") in ("/phpmyadmin", "/pma", "/admin/pma") or path.startswith("/phpmyadmin/"):
            if method == "POST":
                form = parse_qs(req["body"].decode("utf-8", "replace"))
                pma_u = (form.get("pma_username") or [""])[0]
                pma_p = (form.get("pma_password") or [""])[0]
                self.emitter.emit("auth_attempt", **base, username=pma_u, password=pma_p)
                self.emitter.emit("payload", **base, command=f"POST /phpmyadmin/index.php user={pma_u[:40]}",
                                  data={"kind": "web-attack-probe", "category": "credential_access", "threat_score": 75,
                                        "app": "phpmyadmin", "username": pma_u, "password": pma_p})
                err_box = '<div class="err">#1045 - Access denied for user \'' + html.escape(pma_u) + '\'@\'localhost\' (using password: YES)</div>'
                await self._send(writer, 200, PMA_LOGIN_PAGE.replace("{error}", err_box), req=req)
            else:
                await self._send(writer, 200, PMA_LOGIN_PAGE.replace("{error}", ""), req=req)
            return True

        # ── 9. Общий /login (Форма входа + SQLi Auth Bypass) ──
        if path == "/login" and method == "POST":
            form = parse_qs(req["body"].decode("utf-8", "replace"))
            user = (form.get("username") or [""])[0]
            password = (form.get("password") or [""])[0]
            self.emitter.emit("auth_attempt", **base, username=user, password=password)

            # Проверка SQLi в логине/пароле (Auth Bypass)
            if SQLI_RX.search(user) or SQLI_RX.search(password):
                self.emitter.emit("payload", **base, command=f"POST /login SQLi Bypass user={user[:50]}",
                                  data={"kind": "web-attack-probe", "category": "sqli", "threat_score": 92,
                                        "attack_type": "sqli_auth_bypass", "username": user, "password": password})
                # Успешный байпас авторизации -> редирект в дашборд
                await self._send(writer, 302, "", extra=["Location: /dashboard"], req=req)
                return True

            ok = (user, password) in self.users
            if ok:
                await self._send(writer, 302, "", extra=["Location: /dashboard"], req=req)
            else:
                await asyncio.sleep(random.uniform(0.1, 0.4))
                await self._send(writer, 200, LOGIN_PAGE.replace("{error}", '<p class="e">Invalid username or password.</p>'), req=req)
            return True

        # ── 10. Стандартные страницы портала ──
        if path == "/portal":
            await self._send(writer, 200, PORTAL_PAGE, req=req)
            return True
        elif path in ("/", "/login", "/admin", "/index.html"):
            if method in ("GET", "HEAD"):
                await self._send(writer, 200, LOGIN_PAGE.replace("{error}", ""), req=req)
            else:
                await self._error(writer, 405, req)
            return True
        elif path == "/dashboard":
            body = """<!DOCTYPE html><html><head><title>Dashboard</title></head>
<body style="font-family:sans-serif; padding:30px;">
<h2>Administrative Dashboard</h2>
<p>Welcome, Administrator. Session active.</p>
<ul>
  <li>Database status: Online (MySQL 8.0.36)</li>
  <li>Active nodes: 5 nodes in cluster</li>
  <li>Configuration backup: <a href="/download?file=backup.sql">backup.sql</a></li>
</ul>
</body></html>"""
            await self._send(writer, 200, body, req=req)
            return True
        elif method == "OPTIONS":
            await self._send(writer, 200, "", extra=["Allow: OPTIONS,HEAD,GET,POST"], req=req)
            return True
        elif path.rstrip("/") in FORBIDDEN or path.startswith("/.ht"):
            await self._error(writer, 403, req)
            return True
        else:
            await self._error(writer, 404, req)
            return True

    async def _error(self, writer: asyncio.StreamWriter, status: int, req: dict, close: bool = False) -> None:
        reason, title, text = ERRORS.get(status, ("Error", "Error", "An error occurred."))
        host = (req.get("headers", {}).get("host") or self.service.get("host") or "localhost").split(":")[0][:100]
        body = ERROR_PAGE.format(code=status, reason=reason, title=title, host=host, port=self.service["port"],
                                 server=self.server_header,
                                 text=text.format(method=req.get("method", ""), path=urlsplit(req.get("target", "/")).path[:200]))
        await self._send(writer, status, body, close=close, req=req)

    async def _send(self, writer: asyncio.StreamWriter, status: int, body: str, ctype: str = "text/html; charset=UTF-8",
                    extra: list[str] | None = None, close: bool = False, req: dict | None = None) -> None:
        payload = body.encode("utf-8")
        head_only = bool(req) and req.get("method", "").upper() == "HEAD"
        head = [f"HTTP/1.1 {status} {STATUS.get(status, 'OK')}", f"Date: {formatdate(usegmt=True)}",
                f"Server: {self.server_header}", *(extra or []),
                *(["Vary: Accept-Encoding"] if status == 200 and ctype.startswith("text/html") else []),
                f"Content-Length: {len(payload)}", "Connection: close" if close else "Keep-Alive: timeout=5, max=100",
                *([] if close else ["Connection: Keep-Alive"]), f"Content-Type: {ctype}"]
        writer.write(("\r\n".join(head) + "\r\n\r\n").encode("utf-8") + (b"" if head_only else payload))
        await writer.drain()
