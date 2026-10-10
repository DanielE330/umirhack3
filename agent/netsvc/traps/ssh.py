"""Medium-ловушка SSH: настоящий SSH-протокол (asyncssh), перехват учёток, поддельная оболочка и файловая система."""
from __future__ import annotations

import asyncio
import posixpath
import random
import uuid
from pathlib import Path

import asyncssh

from ..emitter import Emitter

DEFAULT_FILES = {
    "/etc/hostname": "{hostname}\n",
    "/etc/os-release": 'NAME="Ubuntu"\nVERSION="20.04.6 LTS (Focal Fossa)"\nID=ubuntu\nVERSION_ID="20.04"\n',
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                   "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nadmin:x:1000:1000::/home/admin:/bin/bash\n",
    "/home/admin/notes.txt": "TODO: rotate backup keys\n",
}
UNAME = "Linux {hostname} 5.4.0-150-generic #167-Ubuntu SMP Mon May 15 17:35:05 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux"
PS = ("  PID TTY          TIME CMD\n    1 ?        00:00:03 systemd\n  412 ?        00:00:00 sshd\n"
      "  733 ?        00:00:01 cron\n 1290 pts/0    00:00:00 bash\n 1344 pts/0    00:00:00 ps\n")


class FakeFS:
    def __init__(self, hostname: str, honeytokens: list[dict]):
        self.files = {p: c.replace("{hostname}", hostname) for p, c in DEFAULT_FILES.items()}
        self.honey: set[str] = set()
        for tok in honeytokens:
            if tok.get("type") == "file":
                self.files[tok["path"]] = tok.get("content", "")
                self.honey.add(tok["path"])

    def dirs(self) -> set[str]:
        out = {"/", "/etc", "/home", "/root", "/tmp", "/var", "/home/admin"}
        for path in self.files:
            parent = posixpath.dirname(path)
            while parent not in ("/", ""):
                out.add(parent)
                parent = posixpath.dirname(parent)
        return out

    def listdir(self, path: str) -> list[str] | None:
        dirs = self.dirs()
        if path not in dirs:
            return None
        names = {posixpath.basename(p) for p in list(self.files) + list(dirs) if p != "/" and posixpath.dirname(p) == path}
        return sorted(names)


class Session:
    """Состояние одной интерактивной оболочки."""

    def __init__(self, trap: "SshTrap", process: asyncssh.SSHServerProcess, sid: str):
        self.trap, self.process, self.sid = trap, process, sid
        self.user = process.get_extra_info("username") or "root"
        peer = process.get_extra_info("peername") or ("", 0)
        self.base = dict(src_ip=peer[0], src_port=peer[1], dst_port=trap.service["port"], proto="ssh", session_id=sid)
        self.cwd = "/root" if self.user == "root" else f"/home/{self.user}"
        self.pty = process.get_terminal_type() is not None

    def out(self, text: str) -> None:
        self.process.stdout.write(text.replace("\n", "\r\n") if self.pty else text)

    def resolve(self, path: str) -> str:
        return posixpath.normpath(path if path.startswith("/") else posixpath.join(self.cwd, path))

    def run(self, line: str) -> bool:
        """Выполняет строку; False — завершить сессию."""
        line = line.strip()
        if not line:
            return True
        self.trap.emitter.emit("command", **self.base, username=self.user, command=line)
        argv = line.split()
        cmd, args = argv[0], argv[1:]
        fs = self.trap.fs
        if cmd in ("exit", "logout", "quit"):
            return False
        if cmd == "pwd":
            self.out(self.cwd + "\n")
        elif cmd == "whoami":
            self.out(self.user + "\n")
        elif cmd == "id":
            uid = 0 if self.user == "root" else 1000
            self.out(f"uid={uid}({self.user}) gid={uid}({self.user}) groups={uid}({self.user})\n")
        elif cmd == "hostname":
            self.out(self.trap.hostname + "\n")
        elif cmd == "uname":
            self.out((UNAME if "-a" in args else "Linux") .format(hostname=self.trap.hostname) + "\n")
        elif cmd == "ps":
            self.out(PS)
        elif cmd == "cd":
            target = self.resolve(args[0]) if args else ("/root" if self.user == "root" else f"/home/{self.user}")
            if target in fs.dirs():
                self.cwd = target
            else:
                self.out(f"bash: cd: {args[0] if args else target}: No such file or directory\n")
        elif cmd == "ls":
            paths = [a for a in args if not a.startswith("-")]
            target = self.resolve(paths[0]) if paths else self.cwd
            names = fs.listdir(target)
            if names is None:
                self.out(f"ls: cannot access '{paths[0] if paths else target}': No such file or directory\n")
            else:
                self.out("  ".join(names) + ("\n" if names else ""))
        elif cmd == "cat":
            for a in args:
                path = self.resolve(a)
                if path in fs.files:
                    if path in fs.honey:
                        self.trap.emitter.emit("honeytoken", **self.base, username=self.user, command=path,
                                               data={"kind": "file"})
                    self.out(fs.files[path])
                else:
                    self.out(f"cat: {a}: No such file or directory\n")
        elif cmd == "echo":
            self.out(" ".join(args) + "\n")
        elif cmd in ("wget", "curl"):
            self.trap.emitter.emit("payload", **self.base, username=self.user, command=line,
                                   data={"kind": "download-attempt"})
            self.out("Connecting... failed: Connection timed out.\n" if cmd == "wget" else "curl: (28) Connection timed out\n")
        elif cmd == "sudo":
            self.out(f"sudo: a terminal is required to read the password\n")
        else:
            self.out(f"bash: {cmd}: command not found\n")
        return True


class SshTrap:
    def __init__(self, service: dict, config: dict, emitter: Emitter, key_dir: str):
        self.service, self.config, self.emitter, self.key_dir = service, config, emitter, key_dir
        decoys = config.get("decoys", {})
        self.hostname = decoys.get("hostname", "srv-01")
        self.users = {(u["username"], u["password"]) for u in decoys.get("users", [])}
        self.accept_any = decoys.get("accept_any_password", True)
        self.fs = FakeFS(self.hostname, decoys.get("honeytokens", []))
        self.server: asyncssh.SSHAcceptor | None = None
        self._sessions: dict[int, str] = {}

    def _host_key(self) -> asyncssh.SSHKey:
        """Ключ хоста сохраняется: смена отпечатка при каждом запуске выдала бы ловушку."""
        path = Path(self.key_dir) / f"ssh_host_ed25519_{self.service['port']}"
        if path.exists():
            return asyncssh.read_private_key(str(path))
        path.parent.mkdir(parents=True, exist_ok=True)
        key = asyncssh.generate_private_key("ssh-ed25519")
        key.write_private_key(str(path))
        path.chmod(0o600)
        return key

    async def start(self, host: str = "0.0.0.0") -> None:
        banner = (self.service.get("banner") or "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5").removeprefix("SSH-2.0-")
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
            session = Session(trap, process, sid)
            try:
                if process.command:  # ssh host "cmd"
                    session.run(process.command)
                    process.exit(0)
                    return
                session.out(f"Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-150-generic x86_64)\n\n")
                while True:
                    session.out(f"{session.user}@{trap.hostname}:{'~' if session.cwd.startswith(('/root', '/home')) and session.cwd.count('/') <= 2 else session.cwd}"
                                f"{'#' if session.user == 'root' else '$'} ")
                    line = await process.stdin.readline()
                    if not line or not session.run(line):
                        break
                process.exit(0)
            except (asyncssh.Error, ConnectionError, OSError):
                process.exit(1)

        self.server = await asyncssh.create_server(
            Server, host, self.service["port"], server_host_keys=[self._host_key()], process_factory=handler,
            server_version=banner, login_timeout=30, line_editor=True)

    @property
    def port(self) -> int:
        return self.server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        if self.server:
            self.server.close()
            await self.server.wait_closed()
