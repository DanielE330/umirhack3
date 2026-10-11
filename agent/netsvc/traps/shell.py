"""Поддельная bash-оболочка: разбор строки как в настоящем bash (кавычки, `;`, `&&`, `||`, `|`, перенаправления,
переменные, подстановка команд, glob) и набор команд с выводом в духе Ubuntu. Ничего не выполняет на самом хосте."""
from __future__ import annotations

import asyncio
import base64
import binascii
import fnmatch
import hashlib
import posixpath
import random
import re
import socket
import time
from typing import Callable

MAX_OUTPUT = 64 * 1024
MAX_FILE = 256 * 1024
MAX_FILES = 400
MAX_DEPTH = 4
NET_DELAY = (0.4, 1.8)  # время «скачивания» в wget/curl; тесты ставят (0, 0)

OPERATORS = (";;", "&&", "||", ">>", ";", "|", ">", "<", "&")
PRIVATE = ("/etc/shadow", "/etc/sudoers", "/root")  # недоступно не-root

BASE_DIRS = ["/", "/bin", "/boot", "/dev", "/etc", "/etc/ssh", "/etc/cron.d", "/etc/apt", "/home", "/lib", "/media",
             "/mnt", "/opt", "/proc", "/root", "/run", "/sbin", "/srv", "/sys", "/tmp", "/usr", "/usr/bin",
             "/usr/lib", "/usr/local", "/usr/local/bin", "/usr/share", "/usr/sbin", "/var", "/var/backups",
             "/var/cache", "/var/lib", "/var/log", "/var/mail", "/var/spool", "/var/tmp", "/var/www",
             "/var/www/html", "/root/.ssh"]

BASHRC = ("# ~/.bashrc: executed by bash(1) for non-login shells.\n\n# If not running interactively, don't do anything\n"
          "case $- in\n    *i*) ;;\n      *) return;;\nesac\n\nHISTCONTROL=ignoreboth\nshopt -s histappend\n"
          "HISTSIZE=1000\nHISTFILESIZE=2000\n")
PROFILE = ("# ~/.profile: executed by the command interpreter for login shells.\n\nif [ -n \"$BASH_VERSION\" ]; then\n"
           "    if [ -f \"$HOME/.bashrc\" ]; then\n\t. \"$HOME/.bashrc\"\n    fi\nfi\n")
HISTORY = ("apt update\napt upgrade -y\nsystemctl status ssh\ndf -h\ntail -n 50 /var/log/syslog\ncrontab -l\n"
           "ls -la /var/www/html\nsystemctl restart cron\nfree -m\nuptime\n")

CPUINFO = "".join(
    f"processor\t: {i}\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 85\nmodel name\t: Intel(R) Xeon(R) Gold "
    f"6130 CPU @ 2.10GHz\nstepping\t: 4\ncpu MHz\t\t: 2099.998\ncache size\t: 22528 KB\nphysical id\t: 0\nsiblings\t: 2\n"
    f"core id\t\t: {i}\ncpu cores\t: 2\nbogomips\t: 4199.99\nclflush size\t: 64\naddress sizes\t: 46 bits physical, "
    f"48 bits virtual\n\n" for i in range(2))
TOTAL_KB, FREE_KB = 4015924, 1296412
MEMINFO = (f"MemTotal:        {TOTAL_KB} kB\nMemFree:         {FREE_KB} kB\nMemAvailable:    {TOTAL_KB - 912000} kB\n"
           "Buffers:          118724 kB\nCached:          1432060 kB\nSwapCached:            0 kB\nSwapTotal:       2097148 kB\n"
           "SwapFree:        2097148 kB\n")

HELP_FOUND = ("ls cat cd pwd echo printf touch mkdir rm cp mv chmod chown head tail wc grep sort uniq cut tr tee find "
              "whoami id hostname uname date uptime w who last ps df free env export history clear sleep true false "
              "which type file stat base64 md5sum sha256sum ifconfig ip ss netstat sudo su sh bash apt apt-get dpkg "
              "systemctl service crontab wget curl kill pkill nproc lscpu lsb_release hostnamectl dmesg lsof "
              "python3 perl ssh scp tar gzip unzip man less more ln vi vim nano mount passwd").split()


def _stamp(path: str) -> int:
    """Стабильное «время изменения» файла в пределах последних месяцев."""
    h = int(hashlib.md5(path.encode()).hexdigest()[:8], 16)
    return int(time.time()) - 86400 * 20 - (h % (86400 * 200))


class FakeFS:
    """Общая для всех сессий файловая система: правки атакующего остаются до перезапуска, как на настоящем сервере."""

    def __init__(self, hostname: str, honeytokens: list[dict], os_release: str, identity_files: dict[str, str] | None = None):
        self.dirs: set[str] = set(BASE_DIRS)
        self.files: dict[str, str] = {
            "/etc/hostname": f"{hostname}\n",
            "/etc/os-release": os_release,
            "/etc/hosts": f"127.0.0.1 localhost\n127.0.1.1 {hostname}\n\n::1 ip6-localhost ip6-loopback\n",
            "/etc/resolv.conf": "nameserver 127.0.0.53\noptions edns0 trust-ad\n",
            "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                           "bin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
                           "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
                           "syslog:x:107:113::/home/syslog:/usr/sbin/nologin\nsshd:x:109:65534::/run/sshd:/usr/sbin/nologin\n"
                           "admin:x:1000:1000:admin:/home/admin:/bin/bash\n",
            "/etc/shadow": "root:$6$rZ8dQ1xT$u2K3mYb0p1xWc0dQ7eHnV2s8LJk9aFqT5yXvB3nM4oP6rS7tU8iV9wX0yZ1aB2cD3eF4gH5iJ6kL7mN8oP9qR0:19640:0:99999:7:::\n"
                           "daemon:*:19640:0:99999:7:::\nwww-data:*:19640:0:99999:7:::\n"
                           "admin:$6$Qw3eRt5y$Zx9cVb8nM7lK6jH5gF4dS3aP2oI1uY0tR9eW8qA7sD6fG5hJ4kL3zX2cV1bN0mQ9wE8rT7yU6iO5pA4sD3fG2h:19640:0:99999:7:::\n",
            "/etc/group": "root:x:0:\nadm:x:4:syslog,admin\nsudo:x:27:admin\nwww-data:x:33:\nadmin:x:1000:\n",
            "/etc/crontab": "SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n\n"
                            "17 *\t* * *\troot    cd / && run-parts --report /etc/cron.hourly\n",
            "/etc/ssh/sshd_config": "Include /etc/ssh/sshd_config.d/*.conf\nPort 22\nPermitRootLogin yes\n"
                                    "PasswordAuthentication yes\nUsePAM yes\nX11Forwarding yes\nSubsystem sftp /usr/lib/openssh/sftp-server\n",
            "/proc/cpuinfo": CPUINFO, "/proc/meminfo": MEMINFO,
            "/var/log/auth.log": "", "/var/log/syslog": "",
            "/var/www/html/index.html": "<html><body><h1>It works!</h1></body></html>\n",
            "/root/.bashrc": BASHRC, "/root/.profile": PROFILE, "/root/.bash_history": HISTORY,
            "/home/admin/.bashrc": BASHRC, "/home/admin/.profile": PROFILE, "/home/admin/.bash_history": HISTORY,
            "/home/admin/notes.txt": "TODO: rotate backup keys\n",
            **(identity_files or {}),
        }
        self.dirs.update({"/home/admin", "/root/.ssh"})
        for tok in honeytokens:
            if tok.get("type") == "file":
                self.files[tok["path"]] = tok.get("content", "")
        # приманки по умолчанию: хэши паролей и «заметки админа» — любое чтение сигнализирует о разведке
        self.honey = {t["path"] for t in honeytokens if t.get("type") == "file"} | {"/etc/shadow", "/home/admin/notes.txt"}
        self.executable: set[str] = set()
        for path in list(self.files):
            self._mkparents(path)

    def _mkparents(self, path: str) -> None:
        parent = posixpath.dirname(path)
        while parent not in ("/", ""):
            self.dirs.add(parent)
            parent = posixpath.dirname(parent)

    def exists(self, path: str) -> bool:
        return path in self.files or path in self.dirs

    def listdir(self, path: str) -> list[str] | None:
        if path not in self.dirs:
            return None
        names = {posixpath.basename(p) for p in (*self.files, *self.dirs) if p != "/" and posixpath.dirname(p) == path}
        return sorted(names)

    def write(self, path: str, content: str, append: bool = False) -> bool:
        if path in self.dirs or posixpath.dirname(path) not in self.dirs:
            return False
        if path not in self.files and len(self.files) >= MAX_FILES:
            return False
        self.files[path] = ((self.files.get(path, "") + content) if append else content)[:MAX_FILE]
        return True

    def remove(self, path: str, recursive: bool) -> bool:
        if path in self.files:
            del self.files[path]
            return True
        if path in self.dirs and recursive and path not in BASE_DIRS:
            prefix = path.rstrip("/") + "/"
            for p in [p for p in self.files if p.startswith(prefix)]:
                del self.files[p]
            self.dirs = {d for d in self.dirs if d != path and not d.startswith(prefix)}
            return True
        return False


class Result:
    """out — stdout, err — stderr (в трубу и файл не попадает), code — код возврата."""
    __slots__ = ("out", "code", "err")

    def __init__(self, out: str = "", code: int = 0, err: str = ""):
        self.out, self.code, self.err = out, code, err

    @property
    def text(self) -> str:
        return self.err + self.out


class Shell:
    """Состояние одной оболочки. `run_line` возвращает вывод и признак «продолжать сессию»."""

    def __init__(self, fs: FakeFS, user: str, hostname: str, os_release: str, uname: str, boot_time: float,
                 ip: str, ports: list[tuple[int, str]], client_ip: str, emit: Callable[..., None], tty: bool = False,
                 width: int = 80):
        self.fs, self.user, self.hostname = fs, user, hostname
        self.os_release, self.uname_tpl, self.boot_time = os_release, uname, boot_time
        self.ip, self.ports, self.client_ip, self.emit, self.tty, self.width = ip, ports, client_ip, emit, tty, width
        self.euid_root = user == "root"
        self.home = "/root" if user == "root" else f"/home/{user}"
        if user != "root":
            fs.dirs.add(self.home)
            for name, body in ((".bashrc", BASHRC), (".profile", PROFILE)):
                fs.files.setdefault(f"{self.home}/{name}", body)
        self.cwd = self.home
        self.vars = {"HOME": self.home, "USER": user, "LOGNAME": user, "SHELL": "/bin/bash", "LANG": "en_US.UTF-8",
                     "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "PWD": self.cwd,
                     "TERM": "xterm-256color" if tty else "dumb", "HOSTNAME": hostname,
                     "SSH_CLIENT": f"{client_ip} 50122 22", "SHLVL": "1", "_": "/usr/bin/env"}
        self.last = 0
        self.history: list[str] = [h for h in fs.files.get(f"{self.home}/.bash_history", "").splitlines() if h]
        self.depth = 0
        self.alive = True

    # --- служебное ---
    @property
    def pretty(self) -> str:
        m = re.search(r'^PRETTY_NAME="?([^"\n]*)', self.os_release, re.M)
        return m.group(1) if m else "Ubuntu 20.04.6 LTS"

    @property
    def version_id(self) -> str:
        m = re.search(r'^VERSION_ID="?([^"\n]*)', self.os_release, re.M)
        return m.group(1) if m else "20.04"

    def uname(self, flag: str = "-a") -> str:
        full = self.uname_tpl.format(hostname=self.hostname)
        m = re.match(r"Linux \S+ (\S+) (#.*?) x86_64", full)
        release, version = (m.group(1), m.group(2)) if m else ("5.4.0-150-generic", "#167-Ubuntu SMP")
        if flag in ("-a", "--all"):
            return full
        parts = {"s": "Linux", "n": self.hostname, "r": release, "v": version, "m": "x86_64",
                 "p": "x86_64", "i": "x86_64", "o": "GNU/Linux"}
        return " ".join(parts[c] for c in flag.lstrip("-") if c in parts) or "Linux"

    def prompt(self) -> str:
        if self.cwd == self.home:
            where = "~"
        elif self.cwd.startswith(self.home + "/"):
            where = "~" + self.cwd[len(self.home):]
        else:
            where = self.cwd
        return f"{self.user}@{self.hostname}:{where}{'#' if self.euid_root else '$'} "

    def resolve(self, path: str) -> str:
        if path == "~" or path.startswith("~/"):
            path = self.home + path[1:]
        return posixpath.normpath(path if path.startswith("/") else posixpath.join(self.cwd, path))

    def denied(self, path: str) -> bool:
        return not self.euid_root and any(path == p or path.startswith(p + "/") for p in PRIVATE)

    def uptime_seconds(self) -> int:
        return int(time.time() - self.boot_time)

    # --- разбор строки ---
    async def run_line(self, line: str) -> tuple[str, bool]:
        line = line.strip("\r\n")
        if not line.strip():
            return "", True
        self.history.append(line.strip())
        try:
            res = await self._run_list(line)
        except _Syntax as exc:
            res = Result(f"bash: {exc}\n", 2)
            self.last = 2
        except Exception:  # любой сбой эмуляции не должен рвать сессию и выдавать себя трассировкой
            res = Result("", 1)
            self.last = 1
        return res.text[:MAX_OUTPUT], self.alive

    async def _tokenize(self, line: str) -> list[tuple[str, bool] | str]:
        """Список слов (текст, можно_ли_glob) и операторов (строки)."""
        toks: list[tuple[str, bool] | str] = []
        buf, has, glob, i, n = [], False, True, 0, len(line)

        def flush() -> None:
            nonlocal buf, has, glob
            if has:
                toks.append(("".join(buf), glob))
            buf, has, glob = [], False, True

        while i < n:
            c = line[i]
            if c in " \t":
                flush()
                i += 1
            elif c == "#" and not has:
                break
            elif c == "'":
                j = line.find("'", i + 1)
                if j < 0:
                    raise _Syntax("unexpected EOF while looking for matching `''")
                buf.append(line[i + 1:j]); has, glob, i = True, False, j + 1
            elif c == '"':
                j, seg = i + 1, []
                while j < n and line[j] != '"':
                    if line[j] == "\\" and j + 1 < n and line[j + 1] in '"\\$`':
                        seg.append(line[j + 1]); j += 2
                    elif line[j] == "$" or line[j] == "`":
                        text, j = await self._expand_at(line, j)
                        seg.append(text)
                    else:
                        seg.append(line[j]); j += 1
                if j >= n:
                    raise _Syntax("unexpected EOF while looking for matching `\"'")
                buf.append("".join(seg)); has, glob, i = True, False, j + 1
            elif c == "\\" and i + 1 < n:
                buf.append(line[i + 1]); has, glob, i = True, False, i + 2
            elif c in "$`":
                text, i = await self._expand_at(line, i)
                buf.append(text); has = has or bool(text)
            elif c == "~" and not has and (i + 1 >= n or line[i + 1] in "/ \t"):
                buf.append(self.home); has, i = True, i + 1
            else:
                op = next((o for o in OPERATORS if line.startswith(o, i)), None)
                if op and buf == ["2"] and op in (">", ">>"):
                    buf, has = [], False
                    op = "2>&1" if line.startswith(">&1", i) else "2>"
                    toks.append(op)
                    i += 3 if op == "2>&1" else len(">")
                elif op == "&" and line.startswith("&>", i):
                    flush(); toks.append("&>"); i += 2
                elif op:
                    flush()
                    toks.append(op)
                    i += len(op)
                else:
                    buf.append(c); has = True; i += 1
        flush()
        return toks

    async def _expand_at(self, s: str, i: int) -> tuple[str, int]:
        """Подстановка, начинающаяся в позиции i: $VAR, ${VAR}, $?, $(...), `...`."""
        if s[i] == "`":
            j = s.find("`", i + 1)
            if j < 0:
                raise _Syntax("unexpected EOF while looking for matching ``'")
            return (await self._capture(s[i + 1:j])), j + 1
        nxt = s[i + 1] if i + 1 < len(s) else ""
        if nxt == "(":
            depth, j = 1, i + 2
            while j < len(s) and depth:
                depth += (s[j] == "(") - (s[j] == ")")
                j += 1
            if depth:
                raise _Syntax("unexpected EOF while looking for matching `)'")
            return (await self._capture(s[i + 2:j - 1])), j
        if nxt == "{":
            j = s.find("}", i)
            if j < 0:
                raise _Syntax("bad substitution")
            name = s[i + 2:j]
            return self.vars.get(name.split(":-")[0], name.split(":-")[1] if ":-" in name else ""), j + 1
        if nxt == "?":
            return str(self.last), i + 2
        if nxt == "$":
            return "1290", i + 2
        m = re.match(r"[A-Za-z_][A-Za-z0-9_]*", s[i + 1:])
        if m:
            return self.vars.get(m.group(0), ""), i + 1 + m.end()
        return "$", i + 1

    async def _capture(self, inner: str) -> str:
        if self.depth >= MAX_DEPTH:
            return ""
        self.depth += 1
        try:
            res = await self._run_list(inner)
        finally:
            self.depth -= 1
        return res.out.rstrip("\n")

    @staticmethod
    def _split_top(line: str) -> list[tuple[str, str]]:
        """Делит строку на команды по ; && || & вне кавычек и скобок: переменные раскрываются уже при выполнении."""
        segs, join, start, i, n, depth, quote = [], ";", 0, 0, len(line), 0, ""
        while i < n:
            c = line[i]
            if quote:
                if c == "\\" and quote == '"':
                    i += 1
                elif c == quote:
                    quote = ""
            elif c == "\\":
                i += 1
            elif c in "'\"`":
                quote = c
            elif c == "(" and line[i - 1:i] == "$":
                depth += 1
            elif c == ")" and depth:
                depth -= 1
            elif not depth and c == "#" and (i == 0 or line[i - 1] in " \t"):
                break
            elif not depth and c in ";&|":
                two = line[i:i + 2]
                if c == "&" and (line[i + 1:i + 2] == ">" or line[i - 1:i] == ">"):
                    pass
                elif two in ("&&", "||"):
                    segs.append((join, line[start:i])); join, start = two, i + 2; i += 1
                elif c in ";&":
                    segs.append((join, line[start:i])); join, start = ";", i + 1
            i += 1
        if quote:
            raise _Syntax(f"unexpected EOF while looking for matching `{quote}'")
        if depth:
            raise _Syntax("unexpected EOF while looking for matching `)'")
        segs.append((join, line[start:i if i <= n else n]))
        return segs

    async def _run_list(self, line: str) -> Result:
        out, err, last_code = [], [], 0
        segs = self._split_top(line)
        for idx, (join, text) in enumerate(segs):
            if not text.strip():
                if join in ("&&", "||") and idx == len(segs) - 1:
                    raise _Syntax("syntax error: unexpected end of file")
                continue
            if (join == "&&" and last_code != 0) or (join == "||" and last_code == 0):
                continue
            res = await self._run_pipeline(await self._tokenize(text))
            out.append(res.out); err.append(res.err)
            last_code = self.last = res.code
            if not self.alive:
                break
        return Result("".join(out), last_code, "".join(err))

    async def _run_pipeline(self, seg: list) -> Result:
        stages, cur = [], []
        for t in seg:
            if t == "|":
                stages.append(cur); cur = []
            else:
                cur.append(t)
        stages.append(cur)
        data, errs, res = "", [], Result()
        for stage in stages:
            if not stage:
                raise _Syntax("syntax error near unexpected token `|'")
            res = await self._run_simple(stage, data)
            errs.append(res.err)
            data = res.out
        return Result(res.out, res.code, "".join(errs[:-1]) + res.err)

    async def _run_simple(self, stage: list, stdin: str) -> Result:
        words: list[str] = []
        redirect: tuple[str, str] | None = None
        drop_err = merge = False
        i = 0
        while i < len(stage):
            t = stage[i]
            if isinstance(t, str):
                if t == "2>&1":
                    merge = True; i += 1; continue
                if t in (">", ">>", "<", "2>", "&>"):
                    if i + 1 >= len(stage) or isinstance(stage[i + 1], str):
                        raise _Syntax("syntax error near unexpected token `newline'")
                    target = stage[i + 1][0]
                    if t == "<":
                        src = self.resolve(target)
                        if src not in self.fs.files:
                            return Result(code=1, err=f"bash: {target}: No such file or directory\n")
                        stdin = self.fs.files[src]
                    elif t == "2>":
                        drop_err = True
                    else:
                        redirect = (t, target)
                        merge = merge or t == "&>"
                    i += 2
                    continue
                raise _Syntax(f"syntax error near unexpected token `{t}'")
            text, can_glob = t
            words.extend(self._glob(text) if can_glob and re.search(r"[*?\[]", text) else [text])
            i += 1
        # присваивания VAR=value перед командой или отдельно
        while words and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", words[0]):
            k, v = words.pop(0).split("=", 1)
            self.vars[k] = v
        if not words:
            return Result()
        res = await self._exec(words, stdin)
        if res.code != 0 and not res.err:
            res.out, res.err = "", res.out
        if merge:
            res = Result(res.err + res.out, res.code)
        if drop_err:
            res.err = ""
        if redirect:
            op, target = redirect
            path = self.resolve(target)
            if path == "/dev/null":
                return Result(code=res.code, err=res.err)
            if self.denied(path) or not self.fs.write(path, res.out, append=op == ">>"):
                why = "Permission denied" if self.denied(path) else "No such file or directory"
                return Result(code=1, err=f"{res.err}bash: {target}: {why}\n")
            if res.out.strip():  # файл, записанный атакующим (скрипт, ключ, конфиг), — в артефакты
                raw = self.fs.files[path].encode()
                self.emit("payload", command=f"{op} {path}", data={
                    "kind": "write", "filename": path, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                    "content_b64": base64.b64encode(raw[:65536]).decode()})
            return Result(code=res.code, err=res.err)
        return res

    def _glob(self, pattern: str) -> list[str]:
        base = posixpath.dirname(pattern)
        names = self.fs.listdir(self.resolve(base) if base else self.cwd)
        if names is None:
            return [pattern]
        hits = [posixpath.join(base, n) if base else n for n in names
                if fnmatch.fnmatchcase(n, posixpath.basename(pattern)) and (not n.startswith(".") or
                                                                           posixpath.basename(pattern).startswith("."))]
        return hits or [pattern]

    # --- выполнение команд ---
    async def _exec(self, argv: list[str], stdin: str) -> Result:
        cmd, args = argv[0], argv[1:]
        await asyncio.sleep(random.uniform(0.005, 0.04))
        if cmd == "sudo":
            return await self._sudo(args, stdin)
        handler = getattr(self, f"c_{cmd.replace('-', '_').replace('.', '_')}", None)
        if cmd.startswith("/") and not handler:  # /bin/ls, /usr/bin/id …
            handler = getattr(self, f"c_{posixpath.basename(cmd).replace('-', '_')}", None)
            if not handler and not self.fs.exists(cmd):
                return Result(f"bash: {cmd}: No such file or directory\n", 127)
            if not handler:
                return Result(f"bash: {cmd}: Permission denied\n", 126)
        if cmd.startswith("./") or ("/" in cmd and not handler):
            path = self.resolve(cmd)
            if path in self.fs.files and path in self.fs.executable:
                self._run_file(cmd, path)
                await asyncio.sleep(random.uniform(0.2, 1.5))
                return Result()
            if path in self.fs.files:
                return Result(f"bash: {cmd}: Permission denied\n", 126)
            if path in self.fs.dirs:
                return Result(f"bash: {cmd}: Is a directory\n", 126)
            return Result(f"bash: {cmd}: No such file or directory\n", 127)
        if handler is None:
            return Result(f"bash: {cmd}: command not found\n", 127)
        res = await handler(args, stdin)
        res = res if isinstance(res, Result) else Result(res or "")
        if res.code != 0 and not res.err:  # сообщения об ошибках уходят в stderr, а не в трубу и файл
            res.out, res.err = "", res.out
        return res

    async def _sudo(self, args: list[str], stdin: str) -> Result:
        args = [a for a in args if a not in ("-n", "-E", "-S")]
        if args and args[0] == "-l":
            return Result(f"Matching Defaults entries for {self.user} on {self.hostname}:\n    env_reset, mail_badpass\n\n"
                          f"User {self.user} may run the following commands on {self.hostname}:\n    (ALL : ALL) ALL\n")
        if not args:
            return Result("usage: sudo -h | -K | -k | -V\n", 1)
        was = self.euid_root
        self.euid_root = True
        try:
            return await self._exec(args, stdin)
        finally:
            self.euid_root = was

    def _fmt_cols(self, names: list[str]) -> str:
        if not names:
            return ""
        if not self.tty:
            return "\n".join(names) + "\n"
        colw = max(len(n) for n in names) + 2
        per = max(1, self.width // colw)
        rows = -(-len(names) // per)
        lines = []
        for r in range(rows):
            lines.append("".join(n.ljust(colw) for n in names[r::rows]).rstrip())
        return "\n".join(lines) + "\n"

    def _ls_long(self, path: str, name: str, isdir: bool) -> str:
        stamp = _stamp(path)
        when = time.strftime("%b %e %H:%M", time.gmtime(stamp))
        owner = "root" if path.startswith(("/root", "/etc", "/usr", "/var/log", "/bin", "/sbin")) or self.user == "root" and not path.startswith("/home") else self.user
        if path.startswith("/home/admin"):
            owner = "admin"
        size = 4096 if isdir else len(self.fs.files.get(path, "").encode())
        mode = "drwxr-xr-x" if isdir else ("-rw-------" if path.endswith((".bash_history", "shadow")) else "-rw-r--r--")
        links = 2 if isdir else 1
        return f"{mode} {links} {owner:<4} {owner:<4} {size:>5} {when} {name}\n"

    # --- команды: ФС ---
    async def c_pwd(self, a, s):
        return self.cwd + "\n"

    async def c_cd(self, a, s):
        target = self.resolve(a[0] if a and a[0] != "-" else self.home)
        if self.denied(target):
            return Result(f"bash: cd: {a[0]}: Permission denied\n", 1)
        if target in self.fs.dirs:
            self.cwd = self.vars["PWD"] = target
            return Result()
        if target in self.fs.files:
            return Result(f"bash: cd: {a[0]}: Not a directory\n", 1)
        return Result(f"bash: cd: {a[0] if a else target}: No such file or directory\n", 1)

    async def c_ls(self, a, s):
        flags = "".join(x[1:] for x in a if x.startswith("-") and not x.startswith("--"))
        paths = [x for x in a if not x.startswith("-")] or ["."]
        long, show_all = "l" in flags, "a" in flags or "A" in flags
        out, code = [], 0
        for raw in paths:
            path = self.resolve(raw)
            if self.denied(path):
                out.append(f"ls: cannot open directory '{raw}': Permission denied\n"); code = 2; continue
            if path in self.fs.files:
                out.append(self._ls_long(path, raw, False) if long else raw + "\n"); continue
            names = self.fs.listdir(path)
            if names is None:
                out.append(f"ls: cannot access '{raw}': No such file or directory\n"); code = 2; continue
            if len(paths) > 1:
                out.append(f"{raw}:\n")
            shown = [n for n in names if show_all or not n.startswith(".")]
            if show_all:
                shown = [".", ".."] + shown
            if long:
                out.append(f"total {4 * (len(shown) + 1)}\n")
                for n in shown:
                    p = path if n == "." else posixpath.dirname(path) if n == ".." else posixpath.join(path, n)
                    out.append(self._ls_long(p, n, p in self.fs.dirs))
            else:
                out.append(self._fmt_cols(shown))
        return Result("".join(out), code)

    def _read(self, raw: str, honey_path_out: list | None = None):
        path = self.resolve(raw)
        if self.denied(path):
            return None, f"cat: {raw}: Permission denied\n"
        if path in self.fs.files:
            if path in self.fs.honey:
                self.emit("honeytoken", command=path, data={"kind": "file"})
            return self.fs.files[path], None
        if path in self.fs.dirs:
            return None, f"cat: {raw}: Is a directory\n"
        return None, f"cat: {raw}: No such file or directory\n"

    async def c_cat(self, a, s):
        files = [x for x in a if not x.startswith("-")]
        if not files:
            return Result(s)
        out, code = [], 0
        for f in files:
            text, err = (s, None) if f == "-" else self._read(f)
            out.append(err or text)
            code = code or (1 if err else 0)
        return Result("".join(out), code)

    c_less = c_more = c_zcat = c_bat = c_cat

    async def c_head(self, a, s):
        return await self._headtail(a, s, head=True)

    async def c_tail(self, a, s):
        return await self._headtail(a, s, head=False)

    async def _headtail(self, a, s, head: bool):
        n, files, i = 10, [], 0
        while i < len(a):
            if a[i] == "-n" and i + 1 < len(a):
                n = int(a[i + 1]) if a[i + 1].lstrip("+-").isdigit() else 10; i += 2
            elif re.fullmatch(r"-\d+", a[i]):
                n = int(a[i][1:]); i += 1
            elif a[i].startswith("-"):
                i += 1
            else:
                files.append(a[i]); i += 1
        text, code = s, 0
        if files:
            parts = []
            for f in files:
                t, err = self._read(f)
                parts.append(err or t); code = code or (1 if err else 0)
            text = "".join(parts)
        lines = text.splitlines(keepends=True)
        return Result("".join(lines[:n] if head else lines[-n:] if n else []), code)

    async def c_wc(self, a, s):
        files = [x for x in a if not x.startswith("-")]
        text = s
        if files:
            t, err = self._read(files[0])
            if err:
                return Result(err.replace("cat:", "wc:"), 1)
            text = t
        lines, words, size = text.count("\n"), len(text.split()), len(text.encode())
        flags = "".join(x[1:] for x in a if x.startswith("-"))
        if flags:
            vals = {"l": lines, "w": words, "c": size, "m": size}
            return Result(" ".join(str(vals[c]) for c in flags if c in vals) + (f" {files[0]}" if files else "") + "\n")
        return Result(f" {lines}  {words} {size}" + (f" {files[0]}" if files else "") + "\n")

    async def c_grep(self, a, s):
        opts = {x for x in a if x.startswith("-") and len(x) > 1}
        rest = [x for x in a if x not in opts]
        if not rest:
            return Result("Usage: grep [OPTION]... PATTERNS [FILE]...\n", 2)
        pat, files = rest[0], rest[1:]
        flags = re.I if any("i" in o for o in opts) else 0
        invert = any("v" in o for o in opts)
        try:
            rx = re.compile(pat if not any(o.startswith("-F") for o in opts) else re.escape(pat), flags)
        except re.error:
            return Result(f"grep: Unmatched pattern\n", 2)
        sources = []
        for f in files:
            t, err = self._read(f)
            if err:
                sources.append((f, None, err.replace("cat:", "grep:")))
            else:
                sources.append((f, t, None))
        if not files:
            sources = [(None, s, None)]
        out, hit = [], False
        for name, text, err in sources:
            if err:
                out.append(err); continue
            for ln in text.splitlines():
                if bool(rx.search(ln)) != invert:
                    hit = True
                    out.append((f"{name}:" if len(files) > 1 else "") + ln + "\n")
        if any("c" in o for o in opts):
            return Result(f"{len([o for o in out])}\n", 0 if hit else 1)
        return Result("".join(out), 0 if hit else 1)

    c_egrep = c_fgrep = c_grep

    async def c_sort(self, a, s):
        lines = s.splitlines()
        lines.sort(reverse="-r" in a)
        return Result("".join(l + "\n" for l in lines))

    async def c_uniq(self, a, s):
        out, prev = [], None
        for l in s.splitlines():
            if l != prev:
                out.append(l)
            prev = l
        return Result("".join(l + "\n" for l in out))

    async def c_tee(self, a, s):
        for f in [x for x in a if not x.startswith("-")]:
            self.fs.write(self.resolve(f), s, append="-a" in a)
        return Result(s)

    async def c_cut(self, a, s):
        delim, field = "\t", 1
        for i, x in enumerate(a):
            if x.startswith("-d"):
                delim = x[2:] or (a[i + 1] if i + 1 < len(a) else "\t")
            if x.startswith("-f"):
                field = int((x[2:] or a[i + 1]).split(",")[0].split("-")[0] or 1)
        return Result("".join((l.split(delim)[field - 1] if len(l.split(delim)) >= field else l) + "\n" for l in s.splitlines()))

    async def c_tr(self, a, s):
        if len(a) == 2 and len(a[0]) == len(a[1]):
            return Result(s.translate(str.maketrans(a[0], a[1])))
        if len(a) == 2 and a[0] == "-d":
            return Result(s.translate({ord(c): None for c in a[1]}))
        return Result(s)

    async def c_awk(self, a, s):
        prog = next((x for x in a if "print" in x), "")
        m = re.search(r"print\s+\$(\d+)", prog)
        if m:
            idx = int(m.group(1))
            return Result("".join(((l.split()[idx - 1] if idx and len(l.split()) >= idx else l if idx == 0 else "") + "\n")
                                  for l in s.splitlines()))
        return Result(s)

    async def c_echo(self, a, s):
        newline = True
        if a and a[0] == "-n":
            newline, a = False, a[1:]
        text = " ".join(a)
        if a and a[0] == "-e":
            text = " ".join(a[1:]).encode().decode("unicode_escape", "ignore")
        return Result(text + ("\n" if newline else ""))

    async def c_printf(self, a, s):
        if not a:
            return Result("printf: usage: printf [-v var] format [arguments]\n", 2)
        fmt = a[0].encode().decode("unicode_escape", "ignore")
        try:
            return Result(fmt % tuple(a[1:]) if "%" in fmt and a[1:] else re.sub(r"%[sd]", "", fmt))
        except (TypeError, ValueError):
            return Result(fmt)

    async def c_touch(self, a, s):
        for f in [x for x in a if not x.startswith("-")]:
            p = self.resolve(f)
            if p not in self.fs.files and p not in self.fs.dirs and not self.fs.write(p, ""):
                return Result(f"touch: cannot touch '{f}': No such file or directory\n", 1)
        return Result()

    async def c_mkdir(self, a, s):
        parents = "-p" in a
        for f in [x for x in a if not x.startswith("-")]:
            p = self.resolve(f)
            if self.denied(p):
                return Result(f"mkdir: cannot create directory '{f}': Permission denied\n", 1)
            if p in self.fs.dirs or p in self.fs.files:
                if not parents:
                    return Result(f"mkdir: cannot create directory '{f}': File exists\n", 1)
            elif posixpath.dirname(p) not in self.fs.dirs and not parents:
                return Result(f"mkdir: cannot create directory '{f}': No such file or directory\n", 1)
            else:
                self.fs.dirs.add(p)
                self.fs._mkparents(p)
        return Result()

    async def c_rm(self, a, s):
        rec = any(x.startswith("-") and ("r" in x or "R" in x) for x in a)
        force = any(x.startswith("-") and "f" in x for x in a)
        for f in [x for x in a if not x.startswith("-")]:
            p = self.resolve(f)
            if self.denied(p):
                return Result(f"rm: cannot remove '{f}': Permission denied\n", 1)
            if p in ("/", "/etc", "/usr", "/bin", "/var", "/home", "/boot"):
                return Result(f"rm: it is dangerous to operate recursively on '{p}'\nrm: use --no-preserve-root to override this failsafe\n", 1)
            if p in self.fs.dirs and not rec:
                return Result(f"rm: cannot remove '{f}': Is a directory\n", 1)
            if not self.fs.exists(p):
                if not force:
                    return Result(f"rm: cannot remove '{f}': No such file or directory\n", 1)
            elif not self.fs.remove(p, rec):
                return Result(f"rm: cannot remove '{f}': Operation not permitted\n", 1)
        return Result()

    async def c_cp(self, a, s):
        paths = [x for x in a if not x.startswith("-")]
        if len(paths) < 2:
            return Result("cp: missing destination file operand after '%s'\n" % (paths[0] if paths else ""), 1)
        src, dst = self.resolve(paths[0]), self.resolve(paths[-1])
        if src not in self.fs.files:
            return Result(f"cp: cannot stat '{paths[0]}': No such file or directory\n", 1)
        if dst in self.fs.dirs:
            dst = posixpath.join(dst, posixpath.basename(src))
        return Result() if self.fs.write(dst, self.fs.files[src]) else Result(f"cp: cannot create regular file '{paths[-1]}': No such file or directory\n", 1)

    async def c_mv(self, a, s):
        res = await self.c_cp(a, s)
        if res.code == 0:
            await self.c_rm([[x for x in a if not x.startswith("-")][0]], "")
        return Result(res.out.replace("cp:", "mv:"), res.code)

    async def c_chmod(self, a, s):
        rest = [x for x in a if not x.startswith("-")]
        if rest and re.search(r"x|[1357]", rest[0]):
            self.fs.executable.update(self.resolve(f) for f in rest[1:] if self.resolve(f) in self.fs.files)
        if len(rest) >= 2 and not any(self.fs.exists(self.resolve(f)) for f in rest[1:]):
            return Result(f"chmod: cannot access '{rest[1]}': No such file or directory\n", 1)
        return Result()

    async def c_noop(self, a, s):
        return Result()

    c_chown = c_chgrp = c_ln = c_sync = c_umask = c_set = c_unset = c_alias = c_source = c_nohup = c_disown = c_noop

    async def c_stat(self, a, s):
        f = next((x for x in a if not x.startswith("-")), None)
        if not f:
            return Result("stat: missing operand\n", 1)
        p = self.resolve(f)
        if not self.fs.exists(p):
            return Result(f"stat: cannot statx '{f}': No such file or directory\n", 1)
        isdir = p in self.fs.dirs
        size = 4096 if isdir else len(self.fs.files[p].encode())
        t = time.strftime("%Y-%m-%d %H:%M:%S.000000000 +0000", time.gmtime(_stamp(p)))
        return Result(f"  File: {f}\n  Size: {size:<10}\tBlocks: 8          IO Block: 4096   "
                      f"{'directory' if isdir else 'regular file'}\nDevice: 801h/2049d\tInode: {abs(hash(p)) % 900000 + 100000:<10}  "
                      f"Links: 1\nAccess: ({'0755/drwxr-xr-x' if isdir else '0644/-rw-r--r--'})  Uid: (    0/    root)   "
                      f"Gid: (    0/    root)\nAccess: {t}\nModify: {t}\nChange: {t}\n Birth: -\n")

    async def c_file(self, a, s):
        out = []
        for f in a:
            p = self.resolve(f)
            out.append(f"{f}: " + ("directory" if p in self.fs.dirs else "ASCII text" if p in self.fs.files
                                    else "cannot open (No such file or directory)") + "\n")
        return Result("".join(out))

    async def c_find(self, a, s):
        start = self.resolve(a[0] if a and not a[0].startswith("-") else ".")
        name = next((a[i + 1] for i, x in enumerate(a) if x == "-name" and i + 1 < len(a)), None)
        if start not in self.fs.dirs:
            return Result(f"find: ‘{a[0]}’: No such file or directory\n", 1)
        prefix = start.rstrip("/") + "/"
        found = [start] + sorted(p for p in (*self.fs.dirs, *self.fs.files) if p.startswith(prefix))
        found = [p for p in found if not name or fnmatch.fnmatchcase(posixpath.basename(p), name)]
        found = [p for p in found if not self.denied(p)]
        shown = [p if (a and a[0].startswith("/")) else "." + p[len(self.cwd):] if p.startswith(self.cwd) else p for p in found]
        return Result("".join(x + "\n" for x in shown[:500]))

    async def c_which(self, a, s):
        out = [f"/usr/bin/{x}\n" for x in a if hasattr(self, f"c_{x}") and x not in ("cd", "export", "history")]
        return Result("".join(out), 0 if out else 1)

    async def c_type(self, a, s):
        return Result("".join(f"{x} is /usr/bin/{x}\n" if hasattr(self, f"c_{x}") else f"bash: type: {x}: not found\n" for x in a))

    c_command = c_type

    async def c_base64(self, a, s):
        data = s
        files = [x for x in a if not x.startswith("-")]
        if files:
            data, err = self._read(files[0])
            if err:
                return Result(err.replace("cat:", "base64:"), 1)
        if "-d" in a or "--decode" in a:
            try:
                return Result(base64.b64decode("".join(data.split()) + "===").decode("utf-8", "replace"))
            except (binascii.Error, ValueError):
                return Result("base64: invalid input\n", 1)
        enc = base64.b64encode(data.encode()).decode()
        return Result("\n".join(enc[i:i + 76] for i in range(0, len(enc), 76)) + "\n")

    async def c_md5sum(self, a, s, algo="md5"):
        out = []
        for f in a or ["-"]:
            text, err = (s, None) if f == "-" else self._read(f)
            out.append(err or f"{hashlib.new(algo, text.encode()).hexdigest()}  {f}\n")
        return Result("".join(out))

    async def c_sha256sum(self, a, s):
        return await self.c_md5sum(a, s, "sha256")

    async def c_sha1sum(self, a, s):
        return await self.c_md5sum(a, s, "sha1")

    # --- команды: система ---
    async def c_whoami(self, a, s):
        return "root\n" if self.euid_root and self.user == "root" else self.user + "\n"

    async def c_id(self, a, s):
        if self.user == "root":
            return "uid=0(root) gid=0(root) groups=0(root)\n"
        return f"uid=1000({self.user}) gid=1000({self.user}) groups=1000({self.user}),4(adm),27(sudo)\n"

    async def c_hostname(self, a, s):
        return self.hostname + "\n"

    async def c_uname(self, a, s):
        flag = next((x for x in a if x.startswith("-")), "")
        return self.uname(flag or "-s") + "\n"

    async def c_date(self, a, s):
        return time.strftime("%a %b %e %H:%M:%S UTC %Y", time.gmtime()) + "\n"

    async def c_uptime(self, a, s):
        up = self.uptime_seconds()
        days, hours, mins = up // 86400, up // 3600 % 24, up // 60 % 60
        return (f" {time.strftime('%H:%M:%S', time.gmtime())} up {days} days, {hours}:{mins:02d},  1 user,  load average: "
                f"{random.uniform(0, .3):.2f}, {random.uniform(0, .3):.2f}, {random.uniform(0, .3):.2f}\n")

    async def c_w(self, a, s):
        return (await self.c_uptime(a, s)) + (f"USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
                                              f"{self.user:<8} pts/0    {self.client_ip:<16} {time.strftime('%H:%M', time.gmtime())}    0.00s  0.03s  0.00s w\n")

    async def c_who(self, a, s):
        return f"{self.user:<8} pts/0        {time.strftime('%Y-%m-%d %H:%M', time.gmtime())} ({self.client_ip})\n"

    async def c_last(self, a, s):
        day = time.strftime("%a %b %e %H:%M", time.gmtime())
        return (f"{self.user:<8} pts/0        {self.client_ip:<16} {day}   still logged in\nreboot   system boot  "
                f"{self.uname('-r'):<16} {time.strftime('%a %b %e %H:%M', time.gmtime(self.boot_time))}   still running\n\n"
                f"wtmp begins {time.strftime('%a %b %e %H:%M:%S %Y', time.gmtime(self.boot_time - 86400 * 40))}\n")

    async def c_free(self, a, s):
        used = TOTAL_KB - FREE_KB
        if "-h" in a:
            g = lambda kb: f"{kb / 1048576:.1f}Gi"
            return (f"               total        used        free      shared  buff/cache   available\nMem:           {g(TOTAL_KB)}"
                    f"       {g(used - 1432060 - 118724)}       {g(FREE_KB)}       1.0Mi       {g(1550784)}       {g(TOTAL_KB - 912000)}\n"
                    f"Swap:          2.0Gi          0B       2.0Gi\n")
        m = "-m" in a
        v = (lambda kb: kb // 1024) if m else (lambda kb: kb)
        return (f"               total        used        free      shared  buff/cache   available\nMem:     {v(TOTAL_KB):>11} "
                f"{v(used - 1550784):>11} {v(FREE_KB):>11} {v(1024):>11} {v(1550784):>11} {v(TOTAL_KB - 912000):>11}\n"
                f"Swap:    {v(2097148):>11} {0:>11} {v(2097148):>11}\n")

    async def c_df(self, a, s):
        if "-h" in a:
            return ("Filesystem      Size  Used Avail Use% Mounted on\ntmpfs           392M  1.1M  391M   1% /run\n"
                    "/dev/sda2        39G   11G   26G  30% /\ntmpfs           2.0G     0  2.0G   0% /dev/shm\n"
                    "tmpfs           5.0M     0  5.0M   0% /run/lock\n/dev/sda1       511M  6.1M  505M   2% /boot/efi\n")
        return ("Filesystem     1K-blocks     Used Available Use% Mounted on\ntmpfs             401592     1124    400468   1% /run\n"
                "/dev/sda2       40581564 11346204  27184488  30% /\ntmpfs            2007960        0   2007960   0% /dev/shm\n")

    async def c_nproc(self, a, s):
        return "2\n"

    async def c_lscpu(self, a, s):
        return ("Architecture:            x86_64\n  CPU op-mode(s):        32-bit, 64-bit\n  Address sizes:         46 bits physical, 48 bits virtual\n"
                "  Byte Order:            Little Endian\nCPU(s):                  2\n  On-line CPU(s) list:   0,1\n"
                "Vendor ID:               GenuineIntel\n  Model name:            Intel(R) Xeon(R) Gold 6130 CPU @ 2.10GHz\n"
                "    CPU family:          6\n    Thread(s) per core:  1\n    Core(s) per socket:  2\n    Socket(s):           1\n")

    async def c_env(self, a, s):
        return "".join(f"{k}={v}\n" for k, v in self.vars.items())

    c_printenv = c_env

    async def c_export(self, a, s):
        for item in a:
            if "=" in item:
                k, v = item.split("=", 1)
                self.vars[k] = v
        return Result() if a else await self.c_env(a, s)

    async def c_history(self, a, s):
        if a and a[0] == "-c":
            self.history.clear()
            return Result()
        return Result("".join(f"{i:>5}  {h}\n" for i, h in enumerate(self.history[-1000:], 1)))

    async def c_clear(self, a, s):
        return "\x1b[H\x1b[2J\x1b[3J" if self.tty else ""

    async def c_sleep(self, a, s):
        try:
            await asyncio.sleep(min(float(a[0]), 5)) if a else None
        except ValueError:
            return Result(f"sleep: invalid time interval ‘{a[0]}’\n", 1)
        return Result()

    async def c_true(self, a, s):
        return Result()

    async def c_false(self, a, s):
        return Result("", 1)

    c_test = c_false

    async def c_exit(self, a, s):
        self.alive = False
        return Result("logout\n" if self.tty else "")

    c_logout = c_quit = c_exit

    async def c_ps(self, a, s):
        procs = [("root", 1, 0.0, 0.3, "/sbin/init"), ("root", 412, 0.0, 0.5, "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups"),
                 ("root", 288, 0.0, 0.9, "/lib/systemd/systemd-journald"), ("root", 733, 0.0, 0.1, "/usr/sbin/cron -f"),
                 ("syslog", 745, 0.0, 0.2, "/usr/sbin/rsyslogd -n -iNONE"), ("root", 801, 0.0, 0.1, "/sbin/agetty -o -p -- \\u --noclear tty1 linux"),
                 ("root", 1288, 0.0, 0.4, f"sshd: {self.user}@pts/0"), (self.user, 1290, 0.0, 0.1, "-bash"),
                 (self.user, 1344, 0.0, 0.0, "ps " + " ".join(a))]
        if any(p == 80 for p, _ in self.ports):
            procs.insert(5, ("root", 690, 0.0, 0.8, "/usr/sbin/apache2 -k start"))
            procs.insert(6, ("www-data", 701, 0.0, 0.6, "/usr/sbin/apache2 -k start"))
        flags = "".join(a)
        if "aux" in flags or "-ef" in flags or "ef" in flags:
            if "-ef" in flags or "ef" in flags and "aux" not in flags:
                return ("UID          PID    PPID  C STIME TTY          TIME CMD\n" +
                        "".join(f"{u:<8} {p:>7} {0 if p == 1 else 1:>7}  0 {time.strftime('%H:%M', time.gmtime(self.boot_time))} ?        00:00:0{p % 4} {c}\n"
                                for u, p, _, _, c in procs))
            return ("USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n" +
                    "".join(f"{u:<8} {p:>7} {cpu:>4} {mem:>4} {10000 + p * 7:>6} {3000 + p % 900:>5} ?        Ss   "
                            f"{time.strftime('%b%d', time.gmtime(self.boot_time))}   0:0{p % 4} {c}\n" for u, p, cpu, mem, c in procs))
        return ("    PID TTY          TIME CMD\n    1290 pts/0    00:00:00 bash\n    1344 pts/0    00:00:00 ps\n"
                .replace("    1290", "   1290").replace("    1344", "   1344"))

    def _listening(self) -> list[tuple[int, str]]:
        return sorted(self.ports) or [(22, "ssh")]

    async def c_ss(self, a, s):
        rows = "".join(f"tcp   LISTEN 0      128          0.0.0.0:{p:<7}      0.0.0.0:*    users:((\"{'sshd' if n == 'ssh' else 'apache2' if n == 'http' else n}\",pid={412 if n == 'ssh' else 690},fd=3))\n"
                       for p, n in self._listening())
        rows += f"tcp   ESTAB  0      0            {self.ip}:22        {self.client_ip}:50122\n" if "a" in "".join(a) else ""
        return "Netid State  Recv-Q Send-Q   Local Address:Port    Peer Address:Port Process\n" + rows

    async def c_netstat(self, a, s):
        rows = "".join(f"tcp        0      0 0.0.0.0:{p:<5}           0.0.0.0:*               LISTEN      {412 if n == 'ssh' else 690}/{'sshd' if n == 'ssh' else 'apache2'}\n"
                       for p, n in self._listening())
        return ("Active Internet connections (only servers)\nProto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\n" + rows)

    async def c_ifconfig(self, a, s):
        return (f"eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet {self.ip}  netmask 255.255.255.0  broadcast {self.ip.rsplit('.', 1)[0]}.255\n"
                f"        ether 02:3f:5a:1c:9e:44  txqueuelen 1000  (Ethernet)\n        RX packets 482913  bytes 391820113 (391.8 MB)\n"
                f"        TX packets 301127  bytes 41093882 (41.0 MB)\n\nlo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
                f"        inet 127.0.0.1  netmask 255.0.0.0\n        loop  txqueuelen 1000  (Local Loopback)\n")

    async def c_ip(self, a, s):
        if a and a[0] in ("a", "addr", "address"):
            return (f"1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
                    f"    inet 127.0.0.1/8 scope host lo\n       valid_lft forever preferred_lft forever\n"
                    f"2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000\n    link/ether 02:3f:5a:1c:9e:44 brd ff:ff:ff:ff:ff:ff\n"
                    f"    inet {self.ip}/24 brd {self.ip.rsplit('.', 1)[0]}.255 scope global eth0\n       valid_lft forever preferred_lft forever\n")
        if a and a[0] in ("r", "route"):
            gw = self.ip.rsplit(".", 1)[0] + ".1"
            return f"default via {gw} dev eth0 proto static\n{self.ip.rsplit('.', 1)[0]}.0/24 dev eth0 proto kernel scope link src {self.ip}\n"
        return Result("Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }\n", 1)

    async def c_lsb_release(self, a, s):
        ver = self.version_id
        name = {"20.04": "focal", "22.04": "jammy", "24.04": "noble"}.get(ver, "focal")
        return (f"Distributor ID:\tUbuntu\nDescription:\t{self.pretty}\nRelease:\t{ver}\nCodename:\t{name}\n"
                if "-a" in a else f"{self.pretty}\n")

    async def c_hostnamectl(self, a, s):
        return (f" Static hostname: {self.hostname}\n       Icon name: computer-vm\n         Chassis: vm\n    Operating System: {self.pretty}\n"
                f"          Kernel: Linux {self.uname('-r')}\n    Architecture: x86-64\n")

    async def c_dmesg(self, a, s):
        return Result("dmesg: read kernel buffer failed: Operation not permitted\n", 1) if not self.euid_root else \
            f"[    0.000000] Linux version {self.uname('-r')}\n[    0.000000] Command line: BOOT_IMAGE=/vmlinuz root=/dev/sda2 ro quiet\n"

    async def c_lsof(self, a, s):
        return Result()

    async def c_crontab(self, a, s):
        if "-l" in a:
            return Result(f"no crontab for {self.user}\n", 1)
        return Result()

    async def c_systemctl(self, a, s):
        if not self.euid_root and a and a[0] in ("start", "stop", "restart", "enable", "disable"):
            return Result("Failed to " + a[0] + " unit: Interactive authentication required.\nSee system logs and 'systemctl status' for details.\n", 1)
        if a and a[0] == "status":
            unit = a[1] if len(a) > 1 else "-"
            return (f"● {unit}.service - OpenBSD Secure Shell server\n     Loaded: loaded (/lib/systemd/system/{unit}.service; enabled; vendor preset: enabled)\n"
                    f"     Active: active (running) since {time.strftime('%a %Y-%m-%d %H:%M:%S UTC', time.gmtime(self.boot_time))}\n   Main PID: 412 (sshd)\n")
        return Result()

    c_service = c_systemctl

    async def c_apt(self, a, s):
        if not self.euid_root:
            return Result("E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)\nE: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), are you root?\n", 100)
        await asyncio.sleep(random.uniform(0.3, 1.0))
        if a and a[0] in ("update",):
            return ("Hit:1 http://archive.ubuntu.com/ubuntu focal InRelease\nGet:2 http://archive.ubuntu.com/ubuntu focal-updates InRelease [114 kB]\n"
                    "Fetched 114 kB in 1s (118 kB/s)\nReading package lists... Done\nBuilding dependency tree\nAll packages are up to date.\n")
        if a and a[0] == "install":
            pkgs = " ".join(x for x in a[1:] if not x.startswith("-"))
            return Result(f"Reading package lists... Done\nBuilding dependency tree\nE: Unable to locate package {pkgs}\n" if pkgs else "", 100)
        return Result("Reading package lists... Done\nBuilding dependency tree\n0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n")

    c_apt_get = c_aptitude = c_apt

    async def c_dpkg(self, a, s):
        return Result("dpkg: error: need an action option\n", 2) if not a else Result()

    async def c_su(self, a, s):
        await asyncio.sleep(random.uniform(1.2, 2.2))
        return Result("su: Authentication failure\n", 1)

    async def c_passwd(self, a, s):
        return Result("passwd: Authentication token manipulation error\n", 10) if not self.euid_root else Result("passwd: password updated successfully\n")

    async def c_kill(self, a, s):
        return Result()

    c_pkill = c_killall = c_kill

    async def c_man(self, a, s):
        return Result(f"No manual entry for {a[0]}\n", 16) if a else Result("What manual page do you want?\nFor example, try 'man man'.\n", 1)

    async def c_ssh(self, a, s):
        await asyncio.sleep(random.uniform(2, 4))
        host = next((x for x in a if not x.startswith("-")), "host")
        return Result(f"ssh: connect to host {host.split('@')[-1]} port 22: Connection timed out\n", 255)

    c_scp = c_sftp = c_ssh

    async def c_python3(self, a, s):
        return Result()

    c_python = c_perl = c_python3

    async def c_vi(self, a, s):
        return Result()

    c_vim = c_nano = c_vi

    async def c_tar(self, a, s):
        return Result()

    c_gzip = c_gunzip = c_unzip = c_tar

    async def c_mount(self, a, s):
        return ("/dev/sda2 on / type ext4 (rw,relatime)\nproc on /proc type proc (rw,nosuid,nodev,noexec,relatime)\n"
                "sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)\ntmpfs on /run type tmpfs (rw,nosuid,nodev,noexec,relatime,size=401592k,mode=755)\n")

    # --- загрузчики и вложенные оболочки ---
    async def c_wget(self, a, s):
        return await self._download(a, "wget")

    async def c_curl(self, a, s):
        return await self._download(a, "curl")

    async def _download(self, args: list[str], tool: str) -> Result:
        """Загрузка «удаётся»: файл-пустышка кладётся в ФС, чтобы атакующий продолжил (chmod, запуск) и показал вторую стадию."""
        url = next((x for x in args if not x.startswith("-") and (("://" in x) or "." in x)), "")
        self.emit("payload", command=f"{tool} {' '.join(args)}", data={"kind": "download-attempt", "tool": tool, "url": url[:300]})
        if not url:
            return Result(f"{tool}: missing URL\nUsage: wget [OPTION]... [URL]...\n" if tool == "wget" else
                          "curl: try 'curl --help' or 'curl --manual' for more information\n", 1 if tool == "wget" else 2)
        host = re.sub(r"^\w+://", "", url).split("/")[0].split(":")[0].split("@")[-1]
        name = posixpath.basename(re.sub(r"[?#].*", "", url).rstrip("/")) or "index.html"
        if "://" not in url:
            url = "http://" + url
        out_name = None
        for i, x in enumerate(args):
            if x in ("-O", "-o", "--output-document", "--output") and i + 1 < len(args):
                out_name = args[i + 1]
            elif re.fullmatch(r"-[a-zA-Z]*[Oo]", x) and i + 1 < len(args):
                out_name = args[i + 1]
            elif x.startswith(("-O", "-o")) and len(x) > 2 and not x.startswith("--"):
                out_name = x[2:]
        remote_o = tool == "curl" and any(x == "-O" or x == "--remote-name" for x in args)
        to_stdout = out_name == "-" or (tool == "curl" and out_name is None and not remote_o)
        body = f"#!/bin/sh\n# {name}\nexit 0\n"
        size = random.randint(1200, 98000)
        await asyncio.sleep(random.uniform(*NET_DELAY))
        quiet = any(x in ("-q", "-s", "--quiet", "--silent") or re.fullmatch(r"-[a-zA-Z]*[qs][a-zA-Z]*", x) for x in args)
        if to_stdout:
            return Result(body)
        target = self.resolve(out_name or name)
        if not self.fs.write(target, body):
            return Result(f"{target}: Permission denied\n" if tool == "wget" else "curl: (23) Failure writing output to destination\n", 1 if tool == "wget" else 23)
        if quiet:
            return Result()
        shown = out_name or name
        if tool == "curl":
            return Result(f"  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\n"
                          f"                                 Dload  Upload   Total   Spent    Left  Speed\n"
                          f"100 {size}  100 {size}    0     0  {size * 3}      0 --:--:-- --:--:-- --:--:-- {size * 3}\n")
        ip = ".".join(str(random.randint(11, 223)) for _ in range(4)) if not re.fullmatch(r"[\d.]+", host) else host
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        return Result(f"--{ts}--  {url}\nResolving {host} ({host})... {ip}\nConnecting to {host} ({host})|{ip}|:80... connected.\n"
                      f"HTTP request sent, awaiting response... 200 OK\nLength: {size} ({size / 1024:.1f}K) [application/octet-stream]\n"
                      f"Saving to: \u2018{shown}\u2019\n\n{shown:<20} 100%[===================>] {size / 1024:6.2f}K  --.-KB/s    in 0.02s\n\n"
                      f"{ts} (4.10 MB/s) - \u2018{shown}\u2019 saved [{size}/{size}]\n\n")

    def _run_file(self, cmd: str, path: str) -> Result | None:
        """Запуск скачанного файла: фиксируем попытку, вывода нет (как у тихого майнера/скрипта)."""
        self.emit("payload", command=cmd, data={"kind": "execution-attempt", "binary": path})
        return None

    async def _script(self, text: str) -> Result:
        if self.depth >= MAX_DEPTH:
            return Result()
        self.depth += 1
        out = []
        try:
            for ln in text.splitlines():
                r = await self._run_list(ln)
                out.append(r.text)
                self.last = r.code
                if not self.alive:
                    break
        finally:
            self.depth -= 1
        return Result("".join(out), self.last)

    async def c_sh(self, a, s):
        if "-c" in a:
            i = a.index("-c")
            return await self._script(a[i + 1]) if i + 1 < len(a) else Result("bash: -c: option requires an argument\n", 2)
        files = [x for x in a if not x.startswith("-")]
        if files:
            text, err = self._read(files[0])
            if not err:
                self._run_file(" ".join(["sh", *a]), self.resolve(files[0]))
            return Result(err.replace("cat:", f"bash: {files[0]}:").replace(f"bash: {files[0]}: {files[0]}:", f"bash: {files[0]}:"), 127) if err \
                else await self._script(text)
        was = self.alive
        res = await self._script(s)
        self.alive = was
        return res

    c_bash = c_dash = c_zsh = c_eval = c_sh


class _Syntax(Exception):
    pass


def local_ip() -> str:
    """IP, с которого машина выходит наружу (пакетов не отправляется)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("10.255.255.255", 1))
            return sock.getsockname()[0]
    except OSError:
        return "10.20.0.15"
