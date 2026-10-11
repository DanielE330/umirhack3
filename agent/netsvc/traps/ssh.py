"""Medium-ловушка SSH: настоящий SSH-протокол (asyncssh), перехват учёток, поддельная оболочка и файловая система."""
from __future__ import annotations

import asyncio
import posixpath
import random
import socket
import uuid
from pathlib import Path

import asyncssh

from ..emitter import Emitter

FALLBACK_OS_RELEASE = 'NAME="Ubuntu"\nVERSION="20.04.6 LTS (Focal Fossa)"\nID=ubuntu\nVERSION_ID="20.04"\n'
# Типичные ядра Ubuntu по версии: настоящее ядро контейнера (…-pve) выдало бы гипервизор
KERNELS = {
    "20.04": ("5.4.0-150-generic", "#167-Ubuntu SMP Mon May 15 17:35:05 UTC 2023"),
    "22.04": ("5.15.0-122-generic", "#132-Ubuntu SMP Thu Aug 29 13:45:52 UTC 2024"),
    "24.04": ("6.8.0-45-generic", "#45-Ubuntu SMP PREEMPT_DYNAMIC Fri Aug 30 12:02:04 UTC 2024"),
}


def system_identity() -> tuple[str, str]:
    """os-release и uname -a в духе той машины, на которой работает агент: консоль не расходится с баннером и ОС."""
    try:
        os_release = Path("/etc/os-release").read_text()
    except OSError:
        os_release = FALLBACK_OS_RELEASE
    version = next((line.split("=", 1)[1].strip('"') for line in os_release.splitlines()
                    if line.startswith("VERSION_ID=")), "20.04")
    kernel, build = KERNELS.get(version, KERNELS["20.04"])
    return os_release, f"Linux {{hostname}} {kernel} {build} x86_64 x86_64 x86_64 GNU/Linux"


OS_RELEASE, UNAME = system_identity()

DEFAULT_FILES = {
    "/etc/hostname": "{hostname}\n",
    "/etc/os-release": OS_RELEASE,
    "/etc/issue": "Ubuntu 20.04.6 LTS \\n \\l\n\n",
    "/etc/hosts": "127.0.0.1 localhost\n127.0.1.1 {hostname}\n",
    "/etc/resolv.conf": "nameserver 1.1.1.1\nnameserver 8.8.8.8\n",
    "/etc/passwd": (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
        "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
        "sshd:x:110:65534::/run/sshd:/usr/sbin/nologin\n"
        "admin:x:1000:1000::/home/admin:/bin/bash\n"
    ),
    "/etc/shadow": (
        "root:$6$vQ9ZJk$h1oWJj9K3f8w1oK6T1R3m5L7P9Q2e4...:19812:0:99999:7:::\n"
        "daemon:*:19812:0:99999:7:::\n"
        "bin:*:19812:0:99999:7:::\n"
        "sys:*:19812:0:99999:7:::\n"
        "www-data:*:19812:0:99999:7:::\n"
        "admin:$6$8Km2Wq$y4N1p7R9s3L5t2V8x0Z6m1Q3f5...:19812:0:99999:7:::\n"
    ),
    "/proc/cpuinfo": (
        "processor\t: 0\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 79\n"
        "model name\t: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz\ncpu MHz\t\t: 2394.454\n"
        "cache size\t: 35840 KB\nphysical id\t: 0\nsiblings\t: 2\ncore id\t\t: 0\ncpu cores\t: 2\n"
        "flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush "
        "mmx fxsr sse sse2 ht syscall nx lm constant_tsc rep_good nopl cpuid pni pclmulqdq ssse3 fma "
        "cx16 pcid sse4_1 sse4_2 movbe popcnt aes xsave avx f16c rdrand hypervisor\n\n"
    ),
    "/proc/meminfo": (
        "MemTotal:        4012488 kB\nMemFree:         2856128 kB\nMemAvailable:    3318944 kB\n"
        "Buffers:          112340 kB\nCached:           591916 kB\nSwapTotal:       2097148 kB\n"
        "SwapFree:        2097148 kB\n"
    ),
    "/proc/version": (
        "Linux version 5.4.0-150-generic (buildd@lcy02-amd64-006) (gcc version 9.4.0 "
        "(Ubuntu 9.4.0-1ubuntu1~20.04.1)) #167-Ubuntu SMP Mon May 15 17:35:05 UTC 2023\n"
    ),
    "/proc/mounts": (
        "/dev/sda1 / ext4 rw,relatime 0 0\n"
        "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n"
        "sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\n"
        "tmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0\n"
    ),
    "/home/admin/notes.txt": "TODO: rotate backup keys (aws_access_key: AKIAIOSFODNN7EXAMPLE)\n",
    "/root/.bash_history": "apt update\nsystemctl restart sshd\ncat /etc/shadow\nwget https://backup.internal/keys.tar.gz\n",
}

PS = (
    "  PID TTY          TIME CMD\n    1 ?        00:00:03 systemd\n  412 ?        00:00:00 sshd\n"
    "  733 ?        00:00:01 cron\n 1290 pts/0    00:00:00 bash\n 1344 pts/0    00:00:00 ps\n"
)

LSCPU = (
    "Architecture:                    x86_64\n"
    "CPU op-mode(s):                  32-bit, 64-bit\n"
    "Byte Order:                      Little Endian\n"
    "Address sizes:                   39 bits physical, 48 bits virtual\n"
    "CPU(s):                          2\n"
    "On-line CPU(s) list:             0,1\n"
    "Thread(s) per core:              1\n"
    "Core(s) per socket:              2\n"
    "Socket(s):                       1\n"
    "Vendor ID:                       GenuineIntel\n"
    "Model name:                      Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz\n"
    "CPU MHz:                         2394.454\n"
    "BogoMIPS:                        4788.90\n"
    "Virtualization:                  VT-x\n"
    "Hypervisor vendor:               KVM\n"
    "Virtualization type:             full\n"
)

FREE = (
    "              total        used        free      shared  buff/cache   available\n"
    "Mem:        4012488      452104     2856128        1280      704256     3318944\n"
    "Swap:       2097148           0     2097148\n"
)

FREE_M = (
    "              total        used        free      shared  buff/cache   available\n"
    "Mem:           3918         441        2789           1         687        3241\n"
    "Swap:          2047           0        2047\n"
)

FREE_H = (
    "               total        used        free      shared  buff/cache   available\n"
    "Mem:           3.8Gi       441Mi       2.7Gi       1.2Mi       687Mi       3.1Gi\n"
    "Swap:          2.0Gi          0B       2.0Gi\n"
)

DF = (
    "Filesystem     1K-blocks     Used Available Use% Mounted on\n"
    "/dev/root       40629032  8562304  30124800  23% /\n"
    "tmpfs            2006244        0   2006244   0% /dev/shm\n"
    "tmpfs             802496      868    801628   1% /run\n"
    "/dev/sda15        106858     6244    100614   6% /boot/efi\n"
)

IP_ADDR = (
    "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n"
    "    inet 127.0.0.1/8 scope host lo\n"
    "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000\n"
    "    inet 10.20.0.15/24 brd 10.20.0.255 scope global eth0\n"
)

IFCONFIG = (
    "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
    "        inet 10.20.0.15  netmask 255.255.255.0  broadcast 10.20.0.255\n"
    "        ether 02:42:0a:14:00:0f  txqueuelen 1000  (Ethernet)\n\n"
    "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
    "        inet 127.0.0.1  netmask 255.0.0.0\n"
    "        loop  txqueuelen 1000  (Local Loopback)\n"
)

KNOWN_BINARIES = {
    "bash", "sh", "wget", "curl", "python", "python3", "cat", "ls", "grep", "chmod", "rm", "mkdir",
    "ps", "kill", "touch", "tar", "gzip", "iptables", "systemctl", "cron", "sudo", "awk", "sed",
    "head", "tail", "id", "whoami", "uname", "df", "free", "uptime", "crontab", "which",
}


def _split_subcommands(line: str) -> list[tuple[str, str]]:
    """Разбивает командную строку с учётом кавычек на (команда, оператор).
    Операторы: '&&', '||', ';', '|'. Последняя команда имеет оператор ''."""
    subcmds = []
    current: list[str] = []
    in_single = False
    in_double = False
    i = 0
    n = len(line)

    while i < n:
        c = line[i]
        if c == "'" and not in_double:
            in_single = not in_single
            current.append(c)
            i += 1
        elif c == '"' and not in_single:
            in_double = not in_double
            current.append(c)
            i += 1
        elif not in_single and not in_double:
            if line[i:i + 2] in ("&&", "||"):
                op = line[i:i + 2]
                cmd_str = "".join(current).strip()
                if cmd_str:
                    subcmds.append((cmd_str, op))
                current = []
                i += 2
            elif c in (";", "|"):
                cmd_str = "".join(current).strip()
                if cmd_str:
                    subcmds.append((cmd_str, c))
                current = []
                i += 1
            else:
                current.append(c)
                i += 1
        else:
            current.append(c)
            i += 1

    remaining = "".join(current).strip()
    if remaining:
        subcmds.append((remaining, ""))
    return subcmds


class FakeFS:
    def __init__(self, hostname: str, honeytokens: list[dict]):
        self.files = {p: c.replace("{hostname}", hostname) for p, c in DEFAULT_FILES.items()}
        self.extra_dirs: set[str] = set()
        self.honey: set[str] = {"/etc/shadow", "/home/admin/notes.txt", "/root/.bash_history"}
        for tok in honeytokens:
            if tok.get("type") == "file":
                self.files[tok["path"]] = tok.get("content", "")
                self.honey.add(tok["path"])

    def dirs(self) -> set[str]:
        out = {"/", "/etc", "/home", "/root", "/tmp", "/var", "/proc", "/sys", "/dev", "/home/admin", "/usr", "/usr/bin", "/bin"}
        out.update(self.extra_dirs)
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
        """Выполняет строку (включая цепочки &&, ||, ;, |); False — завершить сессию."""
        line = line.strip()
        if not line:
            return True
        self.trap.emitter.emit("command", **self.base, username=self.user, command=line)
        subcmds = _split_subcommands(line)
        if not subcmds:
            return True

        last_exit = 0
        prev_op = ""

        for cmd_part, op in subcmds:
            if prev_op == "&&" and last_exit != 0:
                prev_op = op
                continue
            if prev_op == "||" and last_exit == 0:
                prev_op = op
                continue

            cont, exit_code = self._execute_single(cmd_part)
            if not cont:
                return False
            last_exit = exit_code
            prev_op = op

        return True

    def _execute_single(self, cmd_line: str) -> tuple[bool, int]:
        cmd_line = cmd_line.strip()
        if not cmd_line:
            return True, 0

        # Редирект в файл: echo "..." > /path
        redir_file = None
        redir_append = False
        if ">>" in cmd_line:
            parts = cmd_line.split(">>", 1)
            cmd_line = parts[0].strip()
            redir_file = parts[1].strip().split()[0]
            redir_append = True
        elif ">" in cmd_line:
            parts = cmd_line.split(">", 1)
            cmd_line = parts[0].strip()
            redir_file = parts[1].strip().split()[0]

        argv = cmd_line.split()
        if not argv:
            return True, 0
        cmd, args = argv[0], argv[1:]
        fs = self.trap.fs

        if cmd in ("exit", "logout", "quit"):
            return False, 0

        if cmd == "pwd":
            self.out(self.cwd + "\n")
            return True, 0

        if cmd == "whoami":
            self.out(self.user + "\n")
            return True, 0

        if cmd == "id":
            uid = 0 if self.user == "root" else 1000
            self.out(f"uid={uid}({self.user}) gid={uid}({self.user}) groups={uid}({self.user})\n")
            return True, 0

        if cmd == "hostname":
            self.out(self.trap.hostname + "\n")
            return True, 0

        if cmd == "uname":
            if "-a" in args:
                self.out(UNAME.format(hostname=self.trap.hostname) + "\n")
            elif "-r" in args:
                self.out("5.4.0-150-generic\n")
            elif "-m" in args:
                self.out("x86_64\n")
            else:
                self.out("Linux\n")
            return True, 0

        if cmd == "lscpu":
            self.out(LSCPU)
            return True, 0

        if cmd == "nproc":
            self.out("2\n")
            return True, 0

        if cmd == "free":
            if "-h" in args:
                self.out(FREE_H)
            elif "-m" in args:
                self.out(FREE_M)
            else:
                self.out(FREE)
            return True, 0

        if cmd == "uptime":
            self.out(" 14:28:10 up 28 days,  4:12,  1 user,  load average: 0.08, 0.03, 0.01\n")
            return True, 0

        if cmd == "which":
            found = False
            for a in args:
                if not a.startswith("-") and a in KNOWN_BINARIES:
                    prefix = "/bin" if a in {"bash", "sh", "cat", "ls", "grep", "chmod", "rm", "mkdir", "ps", "kill", "touch", "tar", "gzip", "sed"} else "/usr/bin"
                    self.out(f"{prefix}/{a}\n")
                    found = True
            return True, 0 if found else 1

        if cmd in ("env", "printenv"):
            home = "/root" if self.user == "root" else f"/home/{self.user}"
            self.out(f"SHELL=/bin/bash\nPWD={self.cwd}\nLOGNAME={self.user}\nHOME={home}\nLANG=en_US.UTF-8\n"
                     f"USER={self.user}\nSHLVL=1\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
                     f"_=/usr/bin/env\n")
            return True, 0

        if cmd == "history":
            self.out("  1  sudo apt update\n  2  sudo systemctl status sshd\n  3  ls -la /var/log/\n  4  cat /etc/hosts\n  5  exit\n")
            return True, 0

        if cmd == "crontab":
            if "-l" in args:
                self.out(f"no crontab for {self.user}\n")
            return True, 0

        if cmd == "df":
            self.out(DF)
            return True, 0

        if cmd in ("ip", "ifconfig"):
            self.out(IFCONFIG if cmd == "ifconfig" else IP_ADDR)
            return True, 0

        if cmd == "ps":
            self.out(PS)
            return True, 0

        if cmd == "cd":
            target = self.resolve(args[0]) if args else ("/root" if self.user == "root" else f"/home/{self.user}")
            if target in fs.dirs():
                self.cwd = target
                return True, 0
            self.out(f"bash: cd: {args[0] if args else target}: No such file or directory\n")
            return True, 1

        if cmd == "ls":
            paths = [a for a in args if not a.startswith("-")]
            target = self.resolve(paths[0]) if paths else self.cwd
            names = fs.listdir(target)
            if names is None:
                self.out(f"ls: cannot access '{paths[0] if paths else target}': No such file or directory\n")
                return True, 1
            self.out("  ".join(names) + ("\n" if names else ""))
            return True, 0

        if cmd in ("cat", "head", "tail"):
            targets = [a for a in args if not a.startswith("-")]
            if not targets:
                return True, 0
            all_ok = True
            for a in targets:
                path = self.resolve(a)
                if path in fs.files:
                    if path in fs.honey:
                        self.trap.emitter.emit("honeytoken", **self.base, username=self.user, command=path,
                                               data={"kind": "file"})
                    content = fs.files[path]
                    if cmd == "head":
                        content = "\n".join(content.splitlines()[:10]) + ("\n" if content else "")
                    elif cmd == "tail":
                        content = "\n".join(content.splitlines()[-10:]) + ("\n" if content else "")
                    self.out(content)
                else:
                    self.out(f"{cmd}: {a}: No such file or directory\n")
                    all_ok = False
            return True, 0 if all_ok else 1

        if cmd == "grep":
            pattern = args[0] if args else ""
            files = [a for a in args[1:] if not a.startswith("-")]
            for f in files:
                path = self.resolve(f)
                if path in fs.files:
                    if path in fs.honey:
                        self.trap.emitter.emit("honeytoken", **self.base, username=self.user, command=path,
                                               data={"kind": "file"})
                    lines = [line for line in fs.files[path].splitlines() if pattern in line]
                    if lines:
                        self.out("\n".join(lines) + "\n")
            return True, 0

        if cmd == "echo":
            content = " ".join(args).strip("\"'") + "\n"
            if redir_file:
                target_path = self.resolve(redir_file)
                if redir_append and target_path in fs.files:
                    fs.files[target_path] += content
                else:
                    fs.files[target_path] = content
            else:
                self.out(content)
            return True, 0

        if cmd == "touch":
            for a in args:
                if not a.startswith("-"):
                    fs.files[self.resolve(a)] = ""
            return True, 0

        if cmd == "mkdir":
            for a in args:
                if not a.startswith("-"):
                    fs.extra_dirs.add(self.resolve(a))
            return True, 0

        if cmd == "rm":
            for a in args:
                if not a.startswith("-"):
                    fs.files.pop(self.resolve(a), None)
            return True, 0

        if cmd == "chmod":
            return True, 0

        if cmd == "wget":
            url = next((a for a in args if "://" in a or (not a.startswith("-") and "." in a)), "http://remote/payload")
            fname = "payload.sh"
            if "-O" in args:
                idx = args.index("-O")
                if idx + 1 < len(args):
                    fname = args[idx + 1]
            else:
                parsed_name = posixpath.basename(url.split("?")[0].rstrip("/"))
                if parsed_name:
                    fname = parsed_name
            target_file = self.resolve(fname)
            fs.files[target_file] = "#!/bin/sh\n# simulated payload\n"
            self.trap.emitter.emit("payload", **self.base, username=self.user, command=cmd_line,
                                   data={"kind": "download-attempt", "tool": "wget", "url": url, "filename": fname})
            self.out(f"--2026-10-11 14:32:01--  {url}\n"
                     f"Resolving ... connected.\n"
                     f"HTTP request sent, awaiting response... 200 OK\n"
                     f"Length: 4096 (4.0K) [application/x-sh]\n"
                     f"Saving to: '{fname}'\n\n"
                     f"{fname}             100%[===================>]   4.00K  --.-KB/s    in 0.001s\n\n"
                     f"2026-10-11 14:32:01 (3.82 MB/s) - '{fname}' saved [4096/4096]\n")
            return True, 0

        if cmd == "curl":
            url = next((a for a in args if "://" in a or (not a.startswith("-") and "." in a)), "http://remote/payload")
            fname = "payload.sh"
            if "-o" in args:
                idx = args.index("-o")
                if idx + 1 < len(args):
                    fname = args[idx + 1]
            elif "-O" in args:
                parsed_name = posixpath.basename(url.split("?")[0].rstrip("/"))
                if parsed_name:
                    fname = parsed_name
            target_file = self.resolve(fname)
            fs.files[target_file] = "#!/bin/sh\n# simulated payload\n"
            self.trap.emitter.emit("payload", **self.base, username=self.user, command=cmd_line,
                                   data={"kind": "download-attempt", "tool": "curl", "url": url, "filename": fname})
            return True, 0

        if cmd.startswith("./") or cmd in ("sh", "bash"):
            self.trap.emitter.emit("payload", **self.base, username=self.user, command=cmd_line,
                                   data={"kind": "execution-attempt", "binary": cmd})
            return True, 0

        if cmd == "sudo":
            self.out("sudo: a terminal is required to read the password\n")
            return True, 1

        self.out(f"bash: {cmd}: command not found\n")
        return True, 127


class SshTrap:
    def __init__(self, service: dict, config: dict, emitter: Emitter, key_dir: str):
        self.service, self.config, self.emitter, self.key_dir = service, config, emitter, key_dir
        decoys = config.get("decoys", {})
        # Пустое имя в профиле — берём настоящее имя машины, чтобы консоль совпадала с hostname сервера
        self.hostname = decoys.get("hostname") or socket.gethostname()
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

