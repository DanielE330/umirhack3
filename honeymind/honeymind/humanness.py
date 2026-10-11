"""«Человек или бот» по ЦЕПОЧКЕ событий одной сессии.

Признаки только те, что есть в таблице бэкенда (время, команды, логины) — никаких SSH-баннеров и т. п.
Каждый признак имеет физический смысл:
  • темп: человеку нужно время подумать и набрать, скрипту — нет; у «вежливых» ботов паузы почти одинаковые;
  • связь «длина команды ↔ пауза перед ней»: человек дольше набирает длинные команды, у бота связи нет;
  • опечатки и повторы с исправлением, навигация cd/ls, интерактивные программы (vi, top, man) — следы человека;
  • склейка команд через `;`/`&&`, типовые пробы ботнетов — следы скрипта.

Модель обучена на СИМУЛЯЦИИ людей (реальных людей в публичных логах нет) и на реальных ботах.
Поэтому решение «человек» выдаётся только при высокой уверенности, а иначе — None.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import statistics
from collections import OrderedDict
from pathlib import Path
from typing import Sequence

import numpy as np

from .adapter import KIND_COMMAND, KIND_DOWNLOAD, KIND_LOGIN, CanonEvent

HUMAN_MODEL_VERSION = "honeymind-human-1"
MIN_TIMED_EVENTS = 4
MIN_CMDS_FOR_HUMAN = 3   # вердикт «человек» только по поведению в шелле: по одним логинам медленный брутфорс неотличим

_KNOWN = set("""
ls cd cat pwd whoami id w who uname hostname uptime ps top htop kill pkill killall free df du mount lscpu lspci nproc
netstat ss ip ifconfig route ping curl wget tftp ftp scp ssh chmod chown chattr lockr cp mv rm mkdir rmdir touch echo
printf head tail less more grep egrep find locate which whereis file stat history clear exit logout help man sudo su
passwd chpasswd useradd usermod crontab systemctl service journalctl dmesg env export set unset alias vi vim nano
python python3 perl php ruby gcc make tar gzip gunzip unzip zip base64 dd sh bash busybox nohup sleep awk sed sort uniq
wc cut tr xargs tee nc ncat socat openssl docker kubectl mysql psql apt apt-get yum dnf pip pip3 git date cal last
lastlog finger getent arp hostnamectl lsb_release lsblk lsof ulimit sysctl iptables ufw nvidia-smi enable system shell
linuxshell ll dir tftp sftp screen tmux watch jobs bg fg disown source exec true false test read cd.. yes
""".split())
_INTERACTIVE = {"vi", "vim", "nano", "less", "more", "top", "htop", "man", "mysql", "psql", "watch", "screen", "tmux",
                "su", "passwd"}
_NAV = {"cd", "ls", "pwd", "ll", "dir", "cd.."}
_CHAIN = re.compile(r";|&&|\|\|")
_BOT_PROBE = re.compile(r"/bin/busybox\s+[A-Z]{4,}|^(?:enable|system|shell|linuxshell|sh)$|cat /proc/self/exe|"
                        r"\[mM\]iner|echo\s+-e\s+'\\x|mdrfckr|lockr|chattr -ia|/ip cloud|cat /proc/mounts|"
                        r"cd /tmp \|\| cd|echo 1 && cat /bin/echo|\|chpasswd", re.I)

FEATURES = [
    "log_n_cmd", "log_n_login", "frac_login",
    "log_med_gap", "gap_cv", "log_max_gap", "log_min_gap", "frac_gap_lt_03", "frac_gap_gt_5", "frac_gap_gt_30",
    "log_gap_sd", "frac_near_median",
    "len_gap_corr",
    "log_mean_len", "frac_chained", "frac_probe", "frac_unknown_head", "frac_typo_retry",
    "frac_nav", "frac_interactive", "distinct_ratio", "frac_consec_dup",
    "log_login_med_gap",
]

FEATURE_RU = {
    "log_n_cmd": "число команд", "log_n_login": "число попыток входа", "frac_login": "доля попыток входа",
    "log_med_gap": "типичная пауза между действиями", "gap_cv": "неравномерность пауз", "log_max_gap": "самая длинная пауза",
    "log_min_gap": "самая короткая пауза", "frac_gap_lt_03": "доля мгновенных действий (<0.3 с)",
    "frac_gap_gt_5": "доля пауз > 5 с", "frac_gap_gt_30": "доля пауз > 30 с", "log_gap_sd": "разброс пауз",
    "frac_near_median": "одинаковость пауз", "len_gap_corr": "длинные команды набираются дольше",
    "log_mean_len": "средняя длина команды", "frac_chained": "склейка команд через ; и &&",
    "frac_probe": "типовые пробы ботнетов", "frac_unknown_head": "несуществующие команды",
    "frac_typo_retry": "опечатки с исправлением", "frac_nav": "хождение по папкам (cd/ls)",
    "frac_interactive": "интерактивные программы (vi, top, man)", "distinct_ratio": "разнообразие команд",
    "frac_consec_dup": "повтор одной и той же команды", "log_login_med_gap": "пауза между попытками входа",
}


def _head(cmd: str) -> str:
    c = cmd.strip()
    if not c:
        return ""
    tok = c.split()[0]
    return tok.rsplit("/", 1)[-1] if tok.startswith("/") else tok


def _edit1(a: str, b: str) -> bool:
    """Отличаются ли строки ровно одной правкой (вставка/удаление/замена/перестановка соседних)."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diff = [i for i in range(len(a)) if a[i] != b[i]]
        return len(diff) == 1 or (len(diff) == 2 and diff[1] == diff[0] + 1 and a[diff[0]] == b[diff[1]]
                                  and a[diff[1]] == b[diff[0]])
    if len(a) > len(b):
        a, b = b, a
    for i in range(len(b)):
        if b[:i] + b[i + 1:] == a:
            return True
    return False


def _pearson(x: list[float], y: list[float]) -> float:
    if len(x) < 3:
        return 0.0
    mx, my = statistics.fmean(x), statistics.fmean(y)
    sx = math.sqrt(sum((v - mx) ** 2 for v in x))
    sy = math.sqrt(sum((v - my) ** 2 for v in y))
    if sx == 0 or sy == 0:
        return 0.0
    return sum((a - mx) * (b - my) for a, b in zip(x, y)) / (sx * sy)


def features(events: Sequence[CanonEvent]) -> list[float] | None:
    """Вектор признаков или None, если сигнала мало (меньше MIN_TIMED_EVENTS событий со временем)."""
    ev = [e for e in events if e.ts is not None and e.kind in (KIND_COMMAND, KIND_LOGIN, KIND_DOWNLOAD)]
    ev.sort(key=lambda e: e.ts)
    if len(ev) < MIN_TIMED_EVENTS:
        return None
    gaps = [max(0.0, (b.ts - a.ts).total_seconds()) for a, b in zip(ev, ev[1:])]
    cmds = [(i, e.command or "") for i, e in enumerate(ev) if e.kind == KIND_COMMAND]
    logins = [e for e in ev if e.kind == KIND_LOGIN]
    n = len(ev)
    nc = len(cmds)
    med = statistics.median(gaps)
    mean = statistics.fmean(gaps)
    cv = statistics.pstdev(gaps) / mean if mean > 0 else 0.0
    lg = [math.log(g + 0.05) for g in gaps]
    near = sum(1 for g in gaps if med > 0 and abs(g - med) <= 0.1 * med) / len(gaps)

    # пауза ПЕРЕД командой ↔ её длина (время набора)
    lens, pre = [], []
    for i, c in cmds:
        if i > 0:
            lens.append(float(len(c)))
            pre.append(gaps[i - 1])
    corr = _pearson(lens, [math.log(g + 0.05) for g in pre])

    heads = [_head(c) for _, c in cmds]
    texts = [c.strip() for _, c in cmds]
    unknown = sum(1 for h in heads if h and h not in _KNOWN and not h.startswith(("./", ".", "~", ">")))
    typo_retry = 0
    for a, b in zip(texts, texts[1:]):
        if a != b and (_edit1(a, b) or (_head(a) != _head(b) and _edit1(_head(a), _head(b)))):
            typo_retry += 1
    login_gaps = [max(0.0, (b.ts - a.ts).total_seconds()) for a, b in zip(logins, logins[1:])]

    def frac(k: int, d: int) -> float:
        return k / d if d else 0.0

    return [
        math.log1p(nc), math.log1p(len(logins)), frac(len(logins), n),
        math.log(med + 0.05), min(cv, 10.0), math.log(max(gaps) + 0.05), math.log(min(gaps) + 0.05),
        frac(sum(g < 0.3 for g in gaps), len(gaps)), frac(sum(g > 5 for g in gaps), len(gaps)),
        frac(sum(g > 30 for g in gaps), len(gaps)),
        statistics.pstdev(lg), near,
        corr,
        math.log1p(statistics.fmean(len(t) for t in texts)) if texts else 0.0,
        frac(sum(bool(_CHAIN.search(t)) for t in texts), nc),
        frac(sum(bool(_BOT_PROBE.search(t)) for t in texts), nc),
        frac(unknown, nc), frac(typo_retry, max(nc - 1, 1)),
        frac(sum(h in _NAV for h in heads), nc), frac(sum(h in _INTERACTIVE for h in heads), nc),
        frac(len(set(texts)), nc), frac(sum(a == b for a, b in zip(texts, texts[1:])), max(nc - 1, 1)),
        math.log(statistics.median(login_gaps) + 0.05) if login_gaps else 0.0,
    ]


# ───────────────────────── модель ─────────────────────────
class HumanModel:
    """Логистическая регрессия, сохранённая как ЧИСЛА в JSON (среднее/масштаб признаков, веса, сдвиг).

    Не pickle: загрузка не исполняет код и не зависит от версии scikit-learn. sklearn нужен только для обучения."""

    def __init__(self, mean, scale, coef, intercept: float, meta: dict | None = None):
        self.mean = np.asarray(mean, dtype=float)
        self.scale = np.asarray(scale, dtype=float)
        self.coef = np.asarray(coef, dtype=float)
        self.intercept = float(intercept)
        if not (len(self.mean) == len(self.scale) == len(self.coef) == len(FEATURES)):
            raise ValueError("размер модели не совпадает с числом признаков")
        if not (np.all(np.isfinite(self.mean)) and np.all(np.isfinite(self.coef)) and np.all(self.scale > 0)):
            raise ValueError("в модели нечисловые или нулевые значения")
        self.meta = meta or {}
        self.human_threshold = float(self.meta.get("human_threshold", 0.9))
        self.bot_threshold = float(self.meta.get("bot_threshold", 0.3))

    @classmethod
    def from_pipeline(cls, pipe, meta: dict | None = None) -> "HumanModel":
        sc, clf = pipe.named_steps["sc"], pipe.named_steps["clf"]
        return cls(sc.mean_, sc.scale_, clf.coef_[0], clf.intercept_[0], meta)

    def _z(self, x: list[float]) -> np.ndarray:
        return (np.asarray(x, dtype=float) - self.mean) / self.scale * self.coef

    def proba(self, events: Sequence[CanonEvent]) -> float | None:
        x = features(events)
        if x is None:
            return None
        logit = float(self._z(x).sum() + self.intercept)
        return 1.0 / (1.0 + math.exp(-max(-60.0, min(60.0, logit))))

    def decide(self, events: Sequence[CanonEvent]) -> tuple[bool | None, float | None]:
        """-> (True/False/None, вероятность «человек»). True — только при высокой уверенности и ≥ 3 командах."""
        p = self.proba(events)
        if p is None:
            return None, None
        if p >= self.human_threshold:
            n_cmd = sum(1 for e in events if e.kind == KIND_COMMAND)
            return (True if n_cmd >= MIN_CMDS_FOR_HUMAN else None), p
        return (False if p <= self.bot_threshold else None), p

    def explain(self, events: Sequence[CanonEvent], top: int = 3) -> list[str]:
        """Какие признаки сильнее всего сдвинули решение (вклад признака = вес × нормированное значение)."""
        x = features(events)
        if x is None:
            return []
        z = self._z(x)
        dev = np.asarray(x, dtype=float) - self.mean   # выше или ниже типичного значения в обучении
        idx = np.argsort(-np.abs(z))[:top]
        return [f"{FEATURE_RU.get(FEATURES[i], FEATURES[i])}: {'выше' if dev[i] > 0 else 'ниже'} обычного → "
                f"{'человек' if z[i] > 0 else 'бот'}" for i in idx]

    def save(self, path: str | Path) -> str:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        blob = {"features": FEATURES, "mean": self.mean.tolist(), "scale": self.scale.tolist(),
                "coef": self.coef.tolist(), "intercept": self.intercept, "meta": self.meta}
        path.write_text(json.dumps(blob, ensure_ascii=False, indent=1))
        digest = _sha256(path)
        Path(str(path) + ".sha256").write_text(digest + "\n")
        return digest

    @classmethod
    def load(cls, path: str | Path) -> "HumanModel":
        path = Path(path)
        sidecar = Path(str(path) + ".sha256")
        if not sidecar.exists():
            raise RuntimeError(f"нет {sidecar.name}: отказываюсь загружать модель без контрольной суммы")
        if not hmac.compare_digest(_sha256(path), sidecar.read_text().strip()):
            raise RuntimeError("контрольная сумма модели is_human не совпала — файл изменён")
        blob = json.loads(path.read_text())
        if blob.get("features") != FEATURES:
            raise RuntimeError("модель обучена на другом наборе признаков — переобучите: python train_human.py")
        return cls(blob["mean"], blob["scale"], blob["coef"], blob["intercept"], blob.get("meta"))


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ───────────────────────── «этот сценарий уже видели» ─────────────────────────
def _skeleton(cmd: str) -> str:
    c = cmd.lower()
    c = re.sub(r"(?:https?|ftp|tftp)://\S+", "U", c)
    c = re.sub(r"\d+", "0", c)
    c = re.sub(r"[a-z0-9+/=]{12,}", "X", c)
    return " ".join(c.split())


class ScriptTracker:
    """Помнит «скелеты» последовательностей команд, увиденных в /session (в памяти процесса, LRU).

    Реальный факт из логов Cowrie: из 27 492 сессий с ≥ 4 командами лишь 59 имели последовательность, которой нет в
    других сессиях. Одинаковый сценарий с разных IP — почти наверняка один и тот же скрипт.
    Ограничение: состояние живёт в процессе (рестарт = забыли) и ограничено по размеру."""

    def __init__(self, max_items: int = 50_000, min_cmds: int = 4):
        self.max_items, self.min_cmds = max_items, min_cmds
        self._seen: OrderedDict[str, set[str]] = OrderedDict()

    def key(self, events: Sequence[CanonEvent]) -> str | None:
        cmds = [_skeleton(e.command or "") for e in events if e.kind == KIND_COMMAND and e.command]
        if len(cmds) < self.min_cmds:
            return None
        return hashlib.sha1("\n".join(cmds).encode()).hexdigest()

    def observe(self, events: Sequence[CanonEvent]) -> tuple[int, int]:
        """Регистрирует сессию; -> (сколько раз сценарий видели ДО неё, со скольких разных IP)."""
        k = self.key(events)
        if k is None:
            return 0, 0
        ip = next((e.src_ip for e in events if e.src_ip), None) or "?"
        sid = next((e.session_id for e in events if e.session_id), None) or ip
        ips = self._seen.get(k)
        if ips is None:
            ips = set()
            self._seen[k] = ips
            if len(self._seen) > self.max_items:
                self._seen.popitem(last=False)
        else:
            self._seen.move_to_end(k)
        me = f"{ip}|{sid}"
        others = [x for x in ips if x != me]     # повторный вызов /session для той же сессии не считается
        before = len(others)
        before_ips = len({x.split("|", 1)[0] for x in others} - {ip})
        if len(ips) < 1000:
            ips.add(me)
        return before, before_ips
