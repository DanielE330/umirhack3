"""Medium-ловушка SSH: настоящий SSH-протокол (asyncssh), перехват учёток, поддельная оболочка и файловая система."""
from __future__ import annotations

import asyncio
import random
import socket
import time
import uuid
from pathlib import Path

import asyncssh

from ..emitter import Emitter
from .shell import FakeFS, Shell, local_ip

FALLBACK_OS_RELEASE = 'NAME="Ubuntu"\nVERSION="20.04.6 LTS (Focal Fossa)"\nID=ubuntu\nVERSION_ID="20.04"\n'
# Типичные ядра Ubuntu по версии: настоящее ядро контейнера (…-pve) выдало бы гипервизор
KERNELS = {"20.04": ("5.4.0-150-generic", "#167-Ubuntu SMP Mon May 15 17:35:05 UTC 2023"),
           "22.04": ("5.15.0-122-generic", "#132-Ubuntu SMP Thu Aug 29 13:45:52 UTC 2024"),
           "24.04": ("6.8.0-45-generic", "#45-Ubuntu SMP PREEMPT_DYNAMIC Fri Aug 30 12:02:04 UTC 2024")}


def system_identity() -> tuple[str, str]:
    """os-release и uname -a в духе той машины, на которой работает агент: консоль не расходится с баннером и ОС."""
    try:
        os_release = Path("/etc/os-release").read_text()
    except OSError:
        os_release = FALLBACK_OS_RELEASE
    if "ID=ubuntu" not in os_release:  # не Ubuntu (например, машина разработчика) — выдаём типовой сервер
        os_release = FALLBACK_OS_RELEASE
    version = next((line.split("=", 1)[1].strip('"') for line in os_release.splitlines()
                    if line.startswith("VERSION_ID=")), "20.04")
    kernel, build = KERNELS.get(version, KERNELS["20.04"])
    return os_release, f"Linux {{hostname}} {kernel} {build} x86_64 x86_64 x86_64 GNU/Linux"


OS_RELEASE, UNAME = system_identity()
# Версия OpenSSH, которую ставит дистрибутив: баннер не должен расходиться с ОС
OPENSSH = {"20.04": "OpenSSH_8.2p1 Ubuntu-4ubuntu0.11", "22.04": "OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
           "24.04": "OpenSSH_9.6p1 Ubuntu-3ubuntu13.5"}
# Порядок алгоритмов OpenSSH 8.x/9.x: по нему ssh-audit и nmap узнают реализацию; asyncssh берёт только поддерживаемые
PREFERRED = {
    "kex_algs": ["curve25519-sha256", "curve25519-sha256@libssh.org", "ecdh-sha2-nistp256", "ecdh-sha2-nistp384",
                 "ecdh-sha2-nistp521", "diffie-hellman-group-exchange-sha256", "diffie-hellman-group16-sha512",
                 "diffie-hellman-group18-sha512", "diffie-hellman-group14-sha256"],
    "encryption_algs": ["chacha20-poly1305@openssh.com", "aes128-ctr", "aes192-ctr", "aes256-ctr",
                        "aes128-gcm@openssh.com", "aes256-gcm@openssh.com"],
    "mac_algs": ["umac-64-etm@openssh.com", "umac-128-etm@openssh.com", "hmac-sha2-256-etm@openssh.com",
                 "hmac-sha2-512-etm@openssh.com", "hmac-sha1-etm@openssh.com", "umac-64@openssh.com",
                 "umac-128@openssh.com", "hmac-sha2-256", "hmac-sha2-512", "hmac-sha1"],
    "compression_algs": ["none", "zlib@openssh.com"],
}
HOST_KEY_TYPES = [("ssh-ed25519", "ed25519", {}), ("ecdsa-sha2-nistp256", "ecdsa", {}),
                  ("ssh-rsa", "rsa", {"key_size": 3072})]


def algorithm_options() -> dict:
    """Только алгоритмы, которые реализует установленный asyncssh, в порядке OpenSSH."""
    try:
        from asyncssh import compression, encryption, kex, mac
        supported = {"kex_algs": kex.get_kex_algs(), "encryption_algs": encryption.get_encryption_algs(),
                     "mac_algs": mac.get_mac_algs(), "compression_algs": compression.get_compression_algs()}
    except Exception:  # внутренний API asyncssh сменился — остаёмся на алгоритмах по умолчанию
        return {}
    out = {}
    for key, wanted in PREFERRED.items():
        have = {a.decode() if isinstance(a, bytes) else a for a in supported[key]}
        chosen = [a for a in wanted if a in have]
        if chosen:
            out[key] = chosen
    return out


def motd(shell: Shell, last_ip: str) -> str:
    """Приветствие как у настоящей Ubuntu: версия и ядро берутся из той же ОС, что видна в консоли."""
    now = time.strftime("%a %b %e %H:%M:%S UTC %Y", time.gmtime())
    prev = time.strftime("%a %b %e %H:%M:%S %Y", time.gmtime(time.time() - random.randint(3600, 86400 * 5)))
    return (f"Welcome to {shell.pretty} (GNU/Linux {shell.uname('-r')} x86_64)\n\n"
            " * Documentation:  https://help.ubuntu.com\n * Management:     https://landscape.canonical.com\n"
            " * Support:        https://ubuntu.com/pro\n\n  System information as of " + now + "\n\n"
            f"  System load:  {random.uniform(0, .2):.2f}               Processes:             {random.randint(98, 130)}\n"
            f"  Usage of /:   30.1% of 38.58GB   Users logged in:       1\n"
            f"  Memory usage: 23%                IPv4 address for eth0: {shell.ip}\n  Swap usage:   0%\n\n"
            "0 updates can be applied immediately.\n\n"
            f"Last login: {prev} from {last_ip}\n")


class SshTrap:
    def __init__(self, service: dict, config: dict, emitter: Emitter, key_dir: str):
        self.service, self.config, self.emitter, self.key_dir = service, config, emitter, key_dir
        decoys = config.get("decoys", {})
        # Пустое имя в профиле — берём настоящее имя машины, чтобы консоль совпадала с hostname сервера
        self.hostname = decoys.get("hostname") or socket.gethostname()
        self.users = {(u["username"], u["password"]) for u in decoys.get("users", [])}
        self.accept_any = decoys.get("accept_any_password", True)
        self.fs = FakeFS(self.hostname, decoys.get("honeytokens", []), OS_RELEASE)
        self.boot_time = time.time() - random.randint(86400 * 3, 86400 * 60)
        self.ip = local_ip()
        self.ports = [(s["port"], s.get("type", "tcp")) for s in config.get("services", [])]
        self.server: asyncssh.SSHAcceptor | None = None
        self._sessions: dict[int, str] = {}

    def _host_keys(self) -> list[asyncssh.SSHKey]:
        """Ключи хоста (ed25519, ecdsa, rsa, как у настоящего sshd) сохраняются: смена отпечатка выдала бы ловушку."""
        keys = []
        for _, kind, opts in HOST_KEY_TYPES:
            path = Path(self.key_dir) / f"ssh_host_{kind}_{self.service['port']}"
            if path.exists():
                keys.append(asyncssh.read_private_key(str(path)))
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            key = asyncssh.generate_private_key(f"ssh-{kind}" if kind != "ecdsa" else "ecdsa-sha2-nistp256", **opts)
            key.write_private_key(str(path))
            path.chmod(0o600)
            keys.append(key)
        return keys

    def _host_key(self) -> asyncssh.SSHKey:
        return self._host_keys()[0]

    async def start(self, host: str = "0.0.0.0") -> None:
        version = next((l.split("=", 1)[1].strip('"') for l in OS_RELEASE.splitlines() if l.startswith("VERSION_ID=")), "20.04")
        banner = (self.service.get("banner") or "SSH-2.0-" + OPENSSH.get(version, OPENSSH["20.04"])).removeprefix("SSH-2.0-")
        trap = self

        class Server(asyncssh.SSHServer):
            def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
                self.conn = conn
                peer = conn.get_extra_info("peername") or ("", 0)
                self.sid = uuid.uuid4().hex[:16]
                trap._sessions[id(conn)] = self.sid
                self.base = dict(src_ip=peer[0], src_port=peer[1], dst_port=trap.service["port"], proto="ssh",
                                 session_id=self.sid)
                trap.emitter.emit("connect", **self.base)

            def connection_lost(self, exc: Exception | None) -> None:
                trap._sessions.pop(id(self.conn), None)
                trap.emitter.emit("session_end", **self.base)

            def begin_auth(self, username: str) -> bool:
                return True

            def password_auth_supported(self) -> bool:
                return True

            async def validate_password(self, username: str, password: str) -> bool:
                trap.emitter.emit("auth_attempt", **self.base, username=username, password=password)
                await asyncio.sleep(random.uniform(0.3, 0.9))  # как у настоящего sshd
                return trap.accept_any or (username, password) in trap.users

        async def handler(process: asyncssh.SSHServerProcess) -> None:
            sid = trap._sessions.get(id(process.channel.get_connection()), uuid.uuid4().hex[:16])
            peer = process.get_extra_info("peername") or ("", 0)
            base = dict(src_ip=peer[0], src_port=peer[1], dst_port=trap.service["port"], proto="ssh", session_id=sid)
            user = process.get_extra_info("username") or "root"
            tty = process.get_terminal_type() is not None
            width = (process.get_terminal_size() or (80,))[0] or 80
            shell = Shell(trap.fs, user, trap.hostname, OS_RELEASE, UNAME, trap.boot_time, trap.ip, trap.ports, peer[0],
                          lambda kind, **kw: trap.emitter.emit(kind, **base, username=user, **kw), tty=tty, width=width)

            def out(text: str) -> None:
                process.stdout.write(text.replace("\n", "\r\n") if tty else text)

            async def run(line: str) -> bool:
                trap.emitter.emit("command", **base, username=user, command=line.strip())
                text, alive = await shell.run_line(line)
                out(text)
                return alive

            try:
                if process.command:  # ssh host "cmd"
                    await run(process.command)
                    process.exit(shell.last)
                    return
                out(motd(shell, "203.0.113.5" if peer[0].startswith("203.") else "198.51.100.23"))
                while True:
                    out(shell.prompt())
                    line = await process.stdin.readline()
                    if not line or (line.strip() and not await run(line)):
                        break
                process.exit(0)
            except (asyncssh.Error, ConnectionError, OSError):
                process.exit(1)

        self.server = await asyncssh.create_server(
            Server, host, self.service["port"], server_host_keys=self._host_keys(), process_factory=handler,
            server_version=banner, login_timeout=120, line_editor=True, **algorithm_options())

    @property
    def port(self) -> int:
        return self.server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        if self.server:
            self.server.close()
            await self.server.wait_closed()
