"""Ядро HoneyMind: гибрид «правила + ML» для одного события и для сессии."""
from __future__ import annotations

import re
import statistics
from dataclasses import dataclass, field
from typing import Any, Iterable

from . import rules
from .adapter import (KIND_COMMAND, KIND_CONNECT, KIND_DOWNLOAD, KIND_END, KIND_HONEYTOKEN, KIND_HTTP, KIND_LOGIN,
                      CanonEvent, canonicalize)
from .humanness import HumanModel, ScriptTracker
from .model import MODEL_VERSION, ThreatModel
from .rules import CATEGORIES, UNKNOWN, title_ru
from .textnorm import normalize

REVIEW_CONFIDENCE = 0.55      # ниже — модель сама не уверена, помечаем needs_review
MODEL_ONLY_DANGER_CONF = 0.70  # «опасно» (score ≥ 60) только по модели, без правила, — лишь при такой уверенности
SHORT_CMD_TOKENS = 2          # «короткая» команда (в токенах) без правил — оценку по одной модели ограничиваем
SHORT_CMD_CAP = 40
MAX_MODEL_ESCALATION = 25     # насколько модель может поднять оценку над сработавшим правилом
UNKNOWN_SCORE = 30            # балл, если нечем оценить (нет модели и не сработали правила)
OBFUSCATION_BONUS = 5

# Небольшой список «дефолтных» пар из публичных ботнет-словарей (Mirai и т. п.): их перебор — фоновый шум.
_COMMON_USERS = {"root", "admin", "user", "test", "guest", "ubuntu", "pi", "oracle", "postgres", "support", "ftp", "git",
                 "administrator", "default", "operator", "service", "ubnt", "vagrant", "debian", "centos", "supervisor"}
_COMMON_PASS = {"", "root", "admin", "password", "123456", "12345", "1234", "12345678", "123456789", "toor", "pass", "test",
                "guest", "default", "raspberry", "ubnt", "changeme", "qwerty", "1q2w3e4r", "letmein", "xc3511", "vizxv",
                "juantech", "7ujmko0admin", "admin123", "password1", "root123", "111111", "000000", "support", "oracle"}


# Правила, срабатывающие на «фирменные» шаги автоматических скриптов (меню IoT-оболочек, пробы busybox, дропперы…)
_BOT_FAMILY_RULES = {"recon_shell_menu", "recon_busybox_arch", "recon_touch_hidden", "recon_echo_marker", "recon_writable_probe",
                     "recon_hidden_file_ops", "dropper_echo_hex", "dropper_script_staging", "dl_busybox_tftp", "dl_and_exec",
                     "recon_cleanup_relative", "evasion_kill_loop"}


# Слабые пароли «по форме», а не по списку: только цифры до 10 знаков (123, 0000, 12345678…), «admin1», «root123», клавиатурные прогулки
_WEAK_PASS_RX = re.compile(r"^(?:\d{1,10}|(?:admin|root|user|test|pass|password|guest)\d{0,4}|qwerty\w{0,4}|1q2w3e\w{0,4}|(.)\1{3,})$")


@dataclass
class Verdict:
    threat_score: int
    category: str
    kind: str = KIND_COMMAND
    is_human: bool | None = None
    confidence: float = 0.0
    needs_review: bool = False
    source: str = "rules"                      # rules | model | hybrid | heuristic
    matched_rules: list[str] = field(default_factory=list)
    mitre: list[str] = field(default_factory=list)
    summary: str = ""
    model_version: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "threat_score": self.threat_score, "category": self.category, "is_human": self.is_human,
            "confidence": round(self.confidence, 3), "needs_review": self.needs_review, "source": self.source,
            "event_kind": self.kind, "matched_rules": self.matched_rules, "mitre": self.mitre,
            "summary": self.summary, "model_version": self.model_version,
        }


def _clamp(x: float) -> int:
    return max(0, min(100, int(round(x))))


def _summary(category: str, score: int, rule_descs: list[str], source: str, conf: float, obf: bool) -> str:
    # В сводке нет ни байта из команды атакующего: её могут показывать в Telegram/панели/LLM → нет канала инъекции.
    parts = [f"{title_ru(category).capitalize()}, оценка {score}/100"]
    if rule_descs:
        parts.append("Основание: " + "; ".join(rule_descs[:2]))
    elif source == "model":
        parts.append(f"Решение модели, уверенность {conf:.0%}")
    if obf:
        parts.append("Обнаружены следы обфускации")
    return ". ".join(parts) + "."


SCRIPT_SEEN_SESSIONS = 2   # сценарий (≥ 4 команды) уже видели в стольких других сессиях…
SCRIPT_SEEN_IPS = 2        # …с не меньшего числа других IP → это тиражируемый скрипт


class Analyzer:
    def __init__(self, model: ThreatModel | None = None, human_model: HumanModel | None = None,
                 tracker: ScriptTracker | None = None):
        self.model = model
        self.human_model = human_model
        self.tracker = tracker if tracker is not None else ScriptTracker()

    # ───────────────────────── команда ─────────────────────────
    def analyze_command(self, cmd: str | None, kind: str = KIND_COMMAND) -> Verdict:
        n = normalize(cmd)
        if not n.text:
            return Verdict(0, "benign", kind=kind, confidence=1.0, source="rules", summary="Пустая команда, оценка 0/100.",
                           model_version=self._ver())
        hits = rules.match(n.lower)
        top = hits[0].rule if hits else None
        pred = self.model.predict(n.original) if self.model else None

        needs_review = n.truncated
        if top and top.final:
            score, cat, source, conf = top.score, top.category, "rules", 1.0
        elif top and pred:
            # Правило задаёт категорию и «пол» оценки; модель может поднять балл, но не более чем на MAX_MODEL_ESCALATION:
            # иначе безобидная разведка превращалась в «destructive» из-за одного слова rm -rf.
            score = max(top.score, min(pred.expected_score, top.score + MAX_MODEL_ESCALATION))
            cat, source, conf = top.category, "hybrid", pred.confidence
            if pred.category != cat and pred.confidence >= 0.9 and CATEGORIES[pred.category].severity > top.score + 30:
                needs_review = True   # модель категорически не согласна с правилом — пусть посмотрит человек
        elif top:
            score, cat, source, conf = top.score, top.category, "rules", 0.9
        elif pred:
            score, cat, source, conf = pred.expected_score, pred.category, "model", pred.confidence
            needs_review = needs_review or conf < REVIEW_CONFIDENCE
            if len(n.lower.split()) <= SHORT_CMD_TOKENS:
                # одно-два слова без сработавших правил: у ML слишком мало материала, чтобы кричать «опасно»
                if score > SHORT_CMD_CAP:
                    score, needs_review = SHORT_CMD_CAP, True
            if score >= rules.DANGER_THRESHOLD and conf < MODEL_ONLY_DANGER_CONF:
                # правило не сработало, модель не уверена → не объявляем «опасно», а отдаём на разбор
                score, needs_review = rules.DANGER_THRESHOLD - 1, True
        else:
            score, cat, source, conf, needs_review = UNKNOWN_SCORE, UNKNOWN, "rules", 0.0, True

        if n.obfuscated and score >= 40:
            score += OBFUSCATION_BONUS
        score = _clamp(score)
        mitre = sorted({m for h in hits[:3] for m in h.rule.mitre})
        return Verdict(score, cat, kind=kind, confidence=conf, needs_review=needs_review, source=source,
                       matched_rules=[h.rule.id for h in hits[:5]], mitre=mitre,
                       summary=_summary(cat, score, [h.rule.desc for h in hits], source, conf, n.obfuscated),
                       model_version=self._ver())

    # ───────────────────────── вход по паролю ─────────────────────────
    def analyze_login(self, username: str | None, password: str | None, success: bool | None = None) -> Verdict:
        u, p = (username or ""), (password or "")
        # Пароль/логин иногда содержат команды (инъекции) — прогоняем через правила.
        inj = rules.match(normalize(f"{u} {p}").lower)
        inj = [h for h in inj if h.score >= 60]
        if inj:
            v = self.analyze_command(f"{u} {p}", kind=KIND_LOGIN)
            v.summary = "Команда внутри учётных данных. " + v.summary
            return v
        weak_pass = p.lower() in _COMMON_PASS or p.lower() == u.lower() or bool(_WEAK_PASS_RX.match(p.lower()))
        generic = u.lower() in _COMMON_USERS and weak_pass
        score = 15 if generic else 28
        if success:
            score += 10
        reason = ("типовая пара из ботнет-словарей" if generic else "нетипичная пара (возможно, целевой подбор или утёкший список)")
        return Verdict(_clamp(score), "credential_attempt", kind=KIND_LOGIN, confidence=0.6, source="heuristic",
                       mitre=["T1110.001" if generic else "T1110.004"],
                       summary=f"Подбор паролей, оценка {_clamp(score)}/100. Основание: {reason}"
                               f"{'; вход удался' if success else ''}.",
                       model_version=self._ver())

    # ───────────────────────── загрузка файла ─────────────────────────
    def analyze_download(self, url: str | None, file_hash: str | None) -> Verdict:
        score = 90 + (3 if file_hash else 0)
        return Verdict(score, "malware_downloader", kind=KIND_DOWNLOAD, confidence=0.9, source="heuristic",
                       matched_rules=["download_event"], mitre=["T1105"],
                       summary=f"Загрузка вредоноса, оценка {score}/100. Основание: ловушка зафиксировала загрузку файла"
                               f"{' (есть хэш для проверки по IoC)' if file_hash else ''}.",
                       model_version=self._ver())

    # ───────────────────────── событие любой схемы ─────────────────────────
    def analyze_event(self, obj: Any) -> Verdict:
        ev = canonicalize(obj)
        return self._analyze_canon(ev)

    def _analyze_canon(self, ev: CanonEvent) -> Verdict:
        if ev.kind == KIND_COMMAND or ev.kind == KIND_HTTP:
            v = self.analyze_command(ev.command, kind=ev.kind)
            if ev.kind == KIND_HTTP and v.source != "rules":
                v.needs_review = True  # правила и модель обучены на shell-командах, а не на HTTP
            return v
        if ev.kind == KIND_LOGIN:
            return self.analyze_login(ev.username, ev.password, ev.success)
        if ev.kind == KIND_DOWNLOAD:
            return self.analyze_download(ev.url, ev.file_hash)
        if ev.kind == KIND_HONEYTOKEN:
            return Verdict(92, "credential_access", kind=ev.kind, confidence=0.95, source="heuristic",
                           matched_rules=["honeytoken_touched"], mitre=["T1552.001"],
                           summary="Кража учётных данных, оценка 92/100. Основание: тронут приманочный файл/ключ "
                                   "(у легитимного пользователя причин для этого нет).", model_version=self._ver())
        if ev.kind in (KIND_CONNECT, KIND_END):
            return Verdict(5, "benign", kind=ev.kind, confidence=0.5, source="heuristic",
                           summary="Служебное событие соединения, оценка 5/100.", model_version=self._ver())
        return Verdict(UNKNOWN_SCORE, UNKNOWN, kind=ev.kind, confidence=0.0, needs_review=True, source="heuristic",
                       summary="Тип события не распознан, нужна ручная проверка.", model_version=self._ver())

    def _ver(self) -> str | None:
        return self.model.meta.get("version", MODEL_VERSION) if self.model else None

    # ───────────────────────── сессия ─────────────────────────
    def analyze_session(self, events: Iterable[Any]) -> dict[str, Any]:
        canon = [canonicalize(e) for e in events]
        canon.sort(key=lambda e: (e.ts is None, e.ts))
        verdicts = [self._analyze_canon(e) for e in canon]
        p_human: float | None = None
        if self.human_model is not None:
            human, p_human = self.human_model.decide(canon)
            method = "model"
            if p_human is None:
                reason = "слишком мало событий со временем для оценки"
            else:
                why = ", ".join(self.human_model.explain(canon))
                reason = (f"модель: вероятность «человек» {p_human:.2f}" + (f" ({why})" if why else "")
                          + ("" if human is not None else " — недостаточно уверенно"))
        else:
            human, reason = estimate_is_human(canon)
            method = "heuristic"
        cmd_v = [v for e, v in zip(canon, verdicts) if e.kind == KIND_COMMAND]
        scripted = sum(1 for v in cmd_v if _BOT_FAMILY_RULES & set(v.matched_rules))
        if human is not False and cmd_v and scripted / len(cmd_v) >= 0.5:
            # медленные боты (ждут ответа между шагами) выглядят «человечно» по темпу — выдаёт содержимое
            human, reason, method = False, "набор команд — типовой скрипт ботнета (пробы/загрузчики), темп не важен", "rules"
        seen, seen_ips = self.tracker.observe(canon)
        if human is not False and seen >= SCRIPT_SEEN_SESSIONS and seen_ips >= SCRIPT_SEEN_IPS:
            human, method = False, "script_tracker"
            reason = f"та же последовательность команд уже была в {seen} других сессиях с {seen_ips} IP — тиражируемый скрипт"
        meaningful = [v for v in verdicts if v.kind not in (KIND_CONNECT, KIND_END)]
        top = max(meaningful, key=lambda v: v.threat_score, default=None)
        cats = []
        for v in meaningful:
            if v.category not in cats and v.category not in ("benign", UNKNOWN):
                cats.append(v.category)
        score = top.threat_score if top else 0
        if len(cats) >= 3:
            score = _clamp(score + 5)  # широкая цепочка действий (разведка → загрузка → закрепление)
        chain = " → ".join(title_ru(c) for c in cats) if cats else "значимых действий нет"
        return {
            "threat_score": score, "category": top.category if top else "benign", "is_human": human,
            "human_probability": None if p_human is None else round(p_human, 3), "human_method": method,
            "human_reason": reason, "script_seen_before": seen, "kill_chain": cats, "n_events": len(canon),
            "needs_review": any(v.needs_review for v in verdicts),
            "summary": f"Сессия: {chain}; максимальная оценка события {top.threat_score if top else 0}/100; "
                       f"{'похоже на скрипт/бота' if human is False else 'похоже на человека' if human else 'тип оператора не определён'}.",
            "events": [v.to_dict() for v in verdicts],
        }


def estimate_is_human(events: list[CanonEvent]) -> tuple[bool | None, str]:
    """Эвристика по темпу действий. НЕ обучена и не проверена на размеченных данных (в публичных логах нет
    меток «человек/бот»), поэтому при недостатке сигнала честно возвращает None.

    Идея: скрипт отправляет весь набор команд за миллисекунды, человеку нужны секунды на ввод и «подумать».
    Проверка на реальных логах показала главный изъян: медленные боты (ждут ответа между шагами) выглядят «человечно»
    по темпу. Поэтому analyze_session дополнительно смотрит на содержимое (типовые пробы/загрузчики → бот), а ветка
    «человек» требует ≥ 5 событий. Подтверждённых людей в проверенных логах не нашлось — ветку True считайте «возможно»."""
    ts = [e.ts for e in events if e.ts is not None and e.kind in (KIND_COMMAND, KIND_LOGIN)]
    if len(ts) < 3:
        return None, "слишком мало событий с временем"
    gaps = [(b - a).total_seconds() for a, b in zip(ts, ts[1:])]
    gaps = [g for g in gaps if g >= 0]
    if len(gaps) < 2:
        return None, "слишком мало интервалов"
    med = statistics.median(gaps)
    if med < 0.5:
        return False, f"медианный интервал между действиями {med:.3f} с — быстрее человека"
    mean = statistics.fmean(gaps)
    cv = (statistics.pstdev(gaps) / mean) if mean > 0 else 0
    if med >= 1.0 and cv >= 0.4 and max(gaps) >= 3.0 and len(gaps) >= 4:
        return True, f"неравномерный темп (медиана {med:.1f} с, вариация {cv:.2f}) и паузы ≥ 3 с"
    return None, f"темп {med:.2f} с без явных признаков человека или скрипта"
