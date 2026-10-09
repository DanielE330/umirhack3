import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import asyncssh

from netsvc.buffer import EventBuffer
from netsvc.center import CenterClient
from netsvc.core import Agent
from netsvc.emitter import Emitter
from netsvc.traps.banner import BannerTrap
from netsvc.traps.http import HttpTrap
from netsvc.traps.ssh import SshTrap


def run(coro):
    return asyncio.run(coro)


def types(buf):
    return [e["type"] for e in buf.peek(100)]


def test_buffer_persists_across_restart_and_dedupes(tmp_path):
    path = str(tmp_path / "q.db")
    b = EventBuffer(path)
    b.add({"uid": "a1", "type": "connect"})
    b.add({"uid": "a1", "type": "connect"})  # тот же uid
    b.add({"uid": "a2", "type": "connect"})
    assert EventBuffer(path).count() == 2     # «перезапуск» агента
    b.delete(["a1"])
    assert [e["uid"] for e in b.peek(10)] == ["a2"]


def test_emitter_truncates_and_can_drop_passwords():
    async def go():
        buf = EventBuffer(":memory:")
        em = Emitter(buf, capture_passwords=False)
        em.emit("auth_attempt", username="u" * 1000, password="secret")
        ev = buf.peek(1)[0]
        assert len(ev["username"]) == 128 and ev["password"] == ""
    run(go())


def test_banner_trap_records_connect_and_payload():
    async def go():
        buf = EventBuffer(":memory:")
        trap = BannerTrap({"port": 0, "banner": "220 FTP ready"}, {"logging": {"max_payload_bytes": 64}}, Emitter(buf))
        await trap.start("127.0.0.1")
        r, w = await asyncio.open_connection("127.0.0.1", trap.port)
        assert (await r.readline()).strip() == b"220 FTP ready"
        w.write(b"USER anonymous\r\n")
        await w.drain()
        w.close()
        await asyncio.sleep(0.3)
        await trap.stop()
        evs = buf.peek(10)
        assert [e["type"] for e in evs] == ["connect", "payload"]
        assert "USER anonymous" in evs[1]["command"] and evs[0]["src_ip"] == "127.0.0.1"
    run(go())


async def http(port, raw: bytes) -> bytes:
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(raw)
    await w.drain()
    data = await asyncio.wait_for(r.read(65536), 5)
    w.close()
    return data


def test_http_trap_login_capture_404_and_honeytoken():
    async def go():
        buf = EventBuffer(":memory:")
        cfg = {"decoys": {"users": [{"username": "admin", "password": "admin123"}],
                          "honeytokens": [{"type": "url", "path": "/backup.sql", "content": "-- dump"}]}}
        trap = HttpTrap({"port": 0, "banner": "Apache/2.4.41 (Ubuntu)"}, cfg, Emitter(buf))
        await trap.start("127.0.0.1")
        page = await http(trap.port, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        assert b"Admin Console" in page and b"Server: Apache/2.4.41" in page
        assert b"404" in (await http(trap.port, b"GET /nope HTTP/1.1\r\nHost: x\r\n\r\n"))
        body = b"username=root&password=toor"
        bad = await http(trap.port, b"POST /login HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n" % len(body) + body)
        assert b"Invalid username" in bad
        good_body = b"username=admin&password=admin123"
        good = await http(trap.port, b"POST /login HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n" % len(good_body) + good_body)
        assert b"302" in good
        assert b"-- dump" in (await http(trap.port, b"GET /backup.sql HTTP/1.1\r\nHost: x\r\n\r\n"))
        await trap.stop()
        evs = buf.peek(50)
        auth = [e for e in evs if e["type"] == "auth_attempt"]
        assert [(a["username"], a["password"]) for a in auth] == [("root", "toor"), ("admin", "admin123")]
        assert any(e["type"] == "honeytoken" and e["command"] == "/backup.sql" for e in evs)
    run(go())


def test_http_trap_survives_garbage():
    async def go():
        buf = EventBuffer(":memory:")
        trap = HttpTrap({"port": 0}, {}, Emitter(buf))
        await trap.start("127.0.0.1")
        await http(trap.port, b"\x16\x03\x01\x00\xa5\x01\x00\x00\xa1\r\n\r\n")           # TLS ClientHello в открытый порт
        await http(trap.port, b"POST / HTTP/1.1\r\nContent-Length: 99999999\r\n\r\n")     # гигантское тело
        assert b"Admin Console" in await http(trap.port, b"GET / HTTP/1.1\r\n\r\n")        # сервер жив
        await trap.stop()
    run(go())


def test_ssh_trap_captures_credentials_commands_honeytoken(tmp_path):
    async def go():
        buf = EventBuffer(":memory:")
        cfg = {"decoys": {"hostname": "db-prod-01", "accept_any_password": True,
                          "honeytokens": [{"type": "file", "path": "/root/.aws/credentials", "content": "AKIAFAKE\n"}]}}
        trap = SshTrap({"port": 0, "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"}, cfg, Emitter(buf), str(tmp_path))
        await trap.start("127.0.0.1")
        async with asyncssh.connect("127.0.0.1", trap.port, username="root", password="hunter2", known_hosts=None) as conn:
            assert "OpenSSH_8.2p1" in conn.get_extra_info("server_version")
            res = await conn.run("cat /root/.aws/credentials")
            assert "AKIAFAKE" in res.stdout
            res = await conn.run("uname -a")
            assert "db-prod-01" in res.stdout
            res = await conn.run("nosuchcmd")
            assert "command not found" in res.stdout
        await asyncio.sleep(0.3)
        await trap.stop()
        evs = buf.peek(50)
        assert ("root", "hunter2") in [(e["username"], e["password"]) for e in evs if e["type"] == "auth_attempt"]
        assert [e["command"] for e in evs if e["type"] == "command"][:1] == ["cat /root/.aws/credentials"]
        assert any(e["type"] == "honeytoken" and e["command"] == "/root/.aws/credentials" for e in evs)
        assert "session_end" in types(buf) and len({e["session_id"] for e in evs if e["session_id"]}) == 1
        # стабильный отпечаток: ключ хоста сохранён и переиспользуется
        again = SshTrap({"port": 0}, cfg, Emitter(buf), str(tmp_path))
        assert again._host_key().export_public_key() == trap._host_key().export_public_key()
    run(go())


def test_ssh_trap_rejects_wrong_password_when_strict(tmp_path):
    async def go():
        buf = EventBuffer(":memory:")
        cfg = {"decoys": {"accept_any_password": False, "users": [{"username": "root", "password": "toor"}]}}
        trap = SshTrap({"port": 0}, cfg, Emitter(buf), str(tmp_path))
        await trap.start("127.0.0.1")
        try:
            await asyncssh.connect("127.0.0.1", trap.port, username="root", password="nope", known_hosts=None,
                                   preferred_auth="password")
            raise AssertionError("вход не должен был пройти")
        except asyncssh.PermissionDenied:
            pass
        async with asyncssh.connect("127.0.0.1", trap.port, username="root", password="toor", known_hosts=None):
            pass
        await trap.stop()
        assert [e["password"] for e in buf.peek(50) if e["type"] == "auth_attempt"][:2] == ["nope", "toor"]
    run(go())


# --- связь с центром: буфер и дослылка ---
class FakeCenter:
    """Минимальный центр: можно «выключить» ответы и посмотреть, что дошло."""

    def __init__(self):
        self.up = True
        self.received: list[dict] = []
        center = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _json(self, code, obj):
                data = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                if not center.up or self.headers.get("Authorization") != "Bearer hf_ok":
                    return self._json(503 if not center.up else 404, {})
                self._json(200, {"rev": "r1", "state": "run", "poll": 1, "cmds": [], "config": {
                    "level": "low", "services": [{"port": 0, "proto": "banner", "banner": "hello"}], "masking": {"jitter": 0}}})

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if not center.up:
                    return self._json(503, {})
                center.received += body["events"]
                self._json(200, {"ok": len(body["events"]), "dup": 0})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server.server_port}"

    def close(self):
        self.server.shutdown()


def test_agent_buffers_while_center_down_and_flushes_after(tmp_path):
    center = FakeCenter()
    center.up = False

    async def go():
        buf = EventBuffer(str(tmp_path / "q.db"))
        agent = Agent(CenterClient(center.url, "hf_ok", timeout=2), buf, str(tmp_path), bind_host="127.0.0.1")
        runner = asyncio.create_task(agent.run())
        for i in range(3):
            agent.emitter.emit("connect", src_ip=f"10.0.0.{i}")
        await asyncio.sleep(1.5)
        assert buf.count() == 3 and not center.received  # центр недоступен: события в буфере, не потеряны
        center.up = True
        for _ in range(100):
            if len(center.received) >= 3:
                break
            await asyncio.sleep(0.2)
        agent.shutdown()
        await runner
        assert {e["src_ip"] for e in center.received} == {"10.0.0.0", "10.0.0.1", "10.0.0.2"}
        assert buf.count() == 0
    try:
        run(go())
    finally:
        center.close()


def test_agent_starts_traps_from_manifest(tmp_path):
    center = FakeCenter()

    async def go():
        buf = EventBuffer(str(tmp_path / "q.db"))
        agent = Agent(CenterClient(center.url, "hf_ok", timeout=2), buf, str(tmp_path), bind_host="127.0.0.1")
        runner = asyncio.create_task(agent.run())
        for _ in range(50):
            if agent.traps:
                break
            await asyncio.sleep(0.1)
        assert agent.traps, "ловушка не запустилась по манифесту"
        r, w = await asyncio.open_connection("127.0.0.1", agent.traps[0].port)
        assert (await r.readline()).strip() == b"hello"
        w.close()
        for _ in range(60):
            if center.received:
                break
            await asyncio.sleep(0.1)
        agent.shutdown()
        await runner
        assert center.received and center.received[0]["type"] == "connect"
    try:
        run(go())
    finally:
        center.close()
