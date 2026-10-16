"""Ядро HoneyMind: гибрид «правила + ML» для одного события и для сессии."""
from __future__ import annotations

import re
import statistics
from dataclasses import dataclass, field
from typing import Any, Iterable

from . import rules
from .adapter import (KIND_COMMAND, KIND_CONNECT, KIND_DOWNLOAD, KIND_END, KIND_HONEYTOKEN, KIND_HTTP, KIND_LOGIN,
                      CanonEvent, canonicalize)
from .clustering import SessionClusterer
from .humanness import HumanModel, ScriptTracker
from .markov import MarkovIntentEngine
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
SEGMENT_MARGIN = 5            # сегмент цепочки побеждает целую команду, только если опаснее хотя бы на столько
MAX_SEGMENTS = 30
_HIDDEN_PAYLOAD = re.compile(r"[A-Za-z0-9+/=]{60,}")
_EXEC_SINK = re.compile(r"\|\s*(?:sudo\s+)?(?:sh|bash|python\d?|perl)\b|\beval\b|\b(?:sh|bash)\s+-c\b")


def split_segments(text: str) -> list[str]:
    """Делит цепочку на простые команды по ; && || | & и переводам строк — вне кавычек. Линейный проход, без регулярок."""
    out: list[str] = []
    buf: list[str] = []
    quote = ""
    i, n = 0, len(text)
    while i < n and len(out) < MAX_SEGMENTS:
        c = text[i]
        if quote:
            buf.append(c)
            if c == quote:
                quote = ""
        elif c in "'\"":
            quote = c
            buf.append(c)
        elif c in ";\n" or (c in "|&" and not (i > 0 and text[i - 1] in "<>") and not (c == "&" and i + 1 < n and text[i + 1] == ">")):
            seg = "".join(buf).strip()
            if seg:
                out.append(seg)
            buf = []
            if i + 1 < n and text[i + 1] == c and c in "|&":
                i += 1
        else:
            buf.append(c)
        i += 1
    seg = "".join(buf).strip()
    if seg and len(out) < MAX_SEGMENTS:
        out.append(seg)
    return out

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


# Библиотеки SSH, которыми пользуются боты. В 36 545 реальных сессиях Cowrie с командами клиент был: Go — 99,2 %,
# libssh/libssh2/JSch/phpseclib/paramiko — остальное; OpenSSH/PuTTY — ни одной (EVALUATION.md §8).
_BOT_SSH_CLIENT = re.compile(r"ssh-2\.0-(?:go\b|libssh|jsch|phpseclib|paramiko|asyncssh|twisted|russh|makiko|perlssh|"
                             r"sshj|apache-sshd|mina|erlang|ruby|nodejs|ssh2js|golang|zgrab|nmap)", re.I)
_DL_TARGET = re.compile(r"(?:https?|ftp|tftp)://[^\s;|&'\"]+/([\w.\-]{1,64})|-[oO]\s*-?\s*([\w./\-]{1,96})|"
                        r"\b(?:tftp|ftpget)\b[^;|&]{0,120}?(?:-r|-l|get)\s+([\w.\-]{1,64})", re.I)


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
                 tracker: ScriptTracker | None = None, markov: MarkovIntentEngine | None = None,
                 clusterer: SessionClusterer | None = None):
        self.model = model
        self.human_model = human_model
        self.tracker = tracker if tracker is not None else ScriptTracker()
        self.markov = markov if markov is not None else MarkovIntentEngine()
        self.clusterer = clusterer if clusterer is not None else SessionClusterer()

    # ───────────────────────── команда ─────────────────────────
    def analyze_command(self, cmd: str | None, kind: str = KIND_COMMAND) -> Verdict:
        n = normalize(cmd)
        if not n.text:
            return Verdict(0, "benign", kind=kind, confidence=1.0, source="rules", summary="Пустая команда, оценка 0/100.",
                           model_version=self._ver())
        whole = self._score(n, self.model.predict(n.original) if self.model else None, kind)
        segs = split_segments(n.text)
        if len(segs) >= 2:
            # Цепочка a; b && c: оцениваем и каждую простую команду — опасный шаг не должен «растворяться» в безобидных.
            seg_norm = [normalize(sg) for sg in segs]
            preds = self.model.predict_many([x.original for x in seg_norm]) if self.model else [None] * len(seg_norm)
            seg_v = [self._score(x, pr, kind, context=n.lower) for x, pr in zip(seg_norm, preds) if x.text]
            # Поднимать оценку цепочки может только сегмент со сработавшим правилом. Модель и так видит всю цепочку,
            # а на одиночном сегменте она ошибается чаще (уборка «rm -rf /tmp/x.sh» → «destructive»).
            seg_v = [v for v in seg_v if v.matched_rules]
            best = max(seg_v, key=lambda v: v.threat_score, default=None)
            if best is not None and best.threat_score >= whole.threat_score + SEGMENT_MARGIN and best.threat_score >= 40:
                whole.threat_score, whole.category = best.threat_score, best.category
                whole.source = f"{best.source}+segment"
                whole.confidence = best.confidence
                whole.needs_review = whole.needs_review or best.needs_review
                whole.matched_rules = list(dict.fromkeys(best.matched_rules + whole.matched_rules))[:6]
                whole.mitre = sorted(set(whole.mitre) | set(best.mitre))
                whole.summary = best.summary.rstrip(".") + ". Опасный шаг найден внутри цепочки команд."
        if whole.threat_score < rules.DANGER_THRESHOLD and _HIDDEN_PAYLOAD.search(n.text) and _EXEC_SINK.search(n.text) \
                and not n.decoded:
            # длинный нераскодированный блок + исполнение: обфускацию не разобрали — не молчим, а отдаём человеку
            whole.needs_review = True
        return whole

    def _score(self, n, pred, kind: str, context: str | None = None) -> Verdict:
        hits = rules.match(n.lower)
        if context is not None:
            # исключения правил (none_of) проверяем по ВСЕЙ цепочке: «chmod 777 /mnt/d» внутри пробы записи — это проба
            hits = [h for h in hits if not h.rule.excluded_by(context)]
        top = hits[0].rule if hits else None

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
        if ev.category and ev.category in rules.CATEGORIES and ev.category not in ("benign", rules.UNKNOWN):
            score = ev.threat_score or rules.CATEGORIES[ev.category].severity
            mitre_map = {
                "sqli": ["T1190"], "xss": ["T1189"], "rce": ["T1059.004", "T1190"],
                "lfi": ["T1005", "T1083"], "log4shell": ["T1190"], "wordpot": ["T1110.001", "T1190"],
                "ransomware": ["T1486"],
            }
            mitre = mitre_map.get(ev.category, ["T1190"])
            return Verdict(score, ev.category, kind=ev.kind, confidence=0.95, source="rules",
                           matched_rules=[f"web_{ev.category}"], mitre=mitre,
                           summary=f"{rules.title_ru(ev.category)}, оценка {score}/100.",
                           model_version=self._ver())
        if ev.kind == KIND_COMMAND or ev.kind == KIND_HTTP:
            v = self.analyze_command(ev.command, kind=ev.kind)
            if ev.kind == KIND_HTTP and v.source != "rules":
                v.needs_review = True  # правила и модель обучены на shell-командах, а не на HTTP
            return v
        if ev.kind == KIND_LOGIN:
            v = self.analyze_login(ev.username, ev.password, ev.success)
            if ev.hassh:
                from .hassh import classify_hassh
                h_res = classify_hassh(ev.hassh, hassh_raw=ev.hassh_raw or "", client_str=ev.client or "")
                if h_res.is_human is False and h_res.matched:
                    v.threat_score = max(v.threat_score, 45)
                    v.category = "bruteforce" if h_res.category == "bruteforce" else v.category
                    v.matched_rules.append(f"hassh_{h_res.category}")
                    v.summary += f" [HASSH: {h_res.client_name}]"
            return v
        if ev.kind == KIND_DOWNLOAD:
            return self.analyze_download(ev.url, ev.file_hash)
        if ev.kind == KIND_HONEYTOKEN:
            if ev.action == "exfiltrated" or (ev.command and "oob" in ev.command.lower()):
                return Verdict(100, "credential_access", kind=ev.kind, confidence=1.0, source="heuristic",
                               matched_rules=["oob_canary_tripped", "data_exfiltrated"], mitre=["T1552.001", "T1041"],
                               summary="Критический инцидент: подтверждена эксфильтрация данных (100/100). "
                                       "Канареечный токен активирован во внешней сети нарушителем!", model_version=self._ver())
            return Verdict(92, "credential_access", kind=ev.kind, confidence=0.95, source="heuristic",
                           matched_rules=["honeytoken_planted" if ev.action == "planted" else "honeytoken_touched"],
                           mitre=["T1552.001"],
                           summary="Кража учётных данных, оценка 92/100. Основание: тронут приманочный файл/ключ "
                                   "(у легитимного пользователя причин для этого нет).", model_version=self._ver())
        if ev.kind in (KIND_CONNECT, KIND_END):
            if ev.kind == KIND_CONNECT and ev.hassh:
                from .hassh import classify_hassh
                h_res = classify_hassh(ev.hassh, hassh_raw=ev.hassh_raw or "", client_str=ev.client or "")
                score = 35 if not h_res.is_human else 5
                cat = "botnet" if (h_res.category == "botnet" or h_res.risk_level == "high") else "benign"
                return Verdict(score, cat, kind=ev.kind, confidence=0.85 if h_res.matched else 0.5,
                               source="hassh" if h_res.matched else "heuristic",
                               matched_rules=[f"hassh_{h_res.category}"] if h_res.matched else [],
                               mitre=["T1595"] if not h_res.is_human else [],
                               summary=h_res.summary_ru, model_version=self._ver())
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
        client = next((e.client for e in canon if e.client), None)
        hassh_val = next((e.hassh for e in canon if e.hassh), None)
        hassh_raw_val = next((e.hassh_raw for e in canon if e.hassh_raw), "")
        hassh_analysis = None
        if hassh_val:
            from .hassh import classify_hassh
            hassh_analysis = classify_hassh(hassh_val, hassh_raw=hassh_raw_val or "", client_str=client or "")
            if human is not False and hassh_analysis.is_human is False:
                human, method = False, "hassh"
                reason = f"HASSH-отпечаток ({hassh_analysis.client_name}) идентифицирован как автоматизированный бот/сканер"
        if human is not False and client and _BOT_SSH_CLIENT.search(client):
            human, method = False, "ssh_client"
            reason = "SSH-клиент — библиотека для автоматизации (так подключаются боты; люди — через OpenSSH/PuTTY)"
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
        dl_exec = _download_then_execute(canon)
        if dl_exec:
            # скачал в одной команде, запустил в другой: по отдельности шаги могли выглядеть мягче, вместе — нет
            score = max(score, 95)
        exfil_tripped = any(e.kind == KIND_HONEYTOKEN and (e.action == "exfiltrated" or (e.command and "oob" in e.command.lower())) for e in canon)
        if exfil_tripped:
            score = 100
        chain = " → ".join(title_ru(c) for c in cats) if cats else "значимых действий нет"

        # Марковский анализ последовательности техник MITRE ATT&CK
        mitre_seq: list[str] = []
        for v in verdicts:
            for m in v.mitre:
                if not mitre_seq or mitre_seq[-1] != m:
                    mitre_seq.append(m)
        intent_res = self.markov.analyze_sequence(mitre_seq)

        summary_parts = [
            f"Сессия: {chain}; максимальная оценка события {top.threat_score if top else 0}/100; "
            f"{'похоже на скрипт/бота' if human is False else 'похоже на человека' if human else 'тип оператора не определён'}."
        ]
        if exfil_tripped:
            summary_parts.append("[Подтверждена эксфильтрация данных нарушителем]")
        if hassh_analysis and hassh_analysis.matched:
            summary_parts.append(f"[HASSH: {hassh_analysis.client_name}]")
        if intent_res.current_technique:
            summary_parts.append(f"[{intent_res.summary_ru}]")

        # Генерация Detection-as-Code (Sigma и YARA)
        from .detection_rules import DetectionRuleSynthesizer
        synth = DetectionRuleSynthesizer()
        rules_bundle = synth.synthesize(
            canon,
            session_id=canon[0].session_id if canon and canon[0].session_id else None,
            threat_score=score,
            category=top.category if top else "benign",
        )

        session_res = {
            "session_id": canon[0].session_id if canon and canon[0].session_id else None,
            "threat_score": score, "category": top.category if top else "benign", "is_human": human,
            "human_probability": None if p_human is None else round(p_human, 3), "human_method": method,
            "human_reason": reason, "script_seen_before": seen, "kill_chain": cats, "n_events": len(canon),
            "download_then_execute": dl_exec, "ssh_client": client,
            "hassh": hassh_val,
            "hassh_profile": hassh_analysis.to_dict() if hassh_analysis else None,
            "exfiltration_confirmed": exfil_tripped,
            "needs_review": any(v.needs_review for v in verdicts),
            "intent_prediction": intent_res.to_dict(),
            "detection_rules": rules_bundle.to_dict(),
            "summary": " ".join(summary_parts),
            "events": [v.to_dict() for v in verdicts],
        }

        # Генерация Dual-Loop отчётов и матрицы MITRE Engage
        from .reports import ReportSynthesizer, evaluate_mitre_engage
        rep_synth = ReportSynthesizer()
        dual_report = rep_synth.synthesize(session_res)
        session_res["mitre_engage"] = evaluate_mitre_engage(session_res)
        session_res["dual_loop_report"] = dual_report.to_dict()

        return session_res

    def predict_intent(self, events_or_techniques: list[Any]) -> dict[str, Any]:
        """Прямой вызов предсказания намерений по списку событий или строк-техник MITRE."""
        if not events_or_techniques:
            return self.markov.analyze_sequence([]).to_dict()
        if isinstance(events_or_techniques[0], str):
            return self.markov.analyze_sequence(events_or_techniques).to_dict()
        canon = [canonicalize(e) for e in events_or_techniques]
        verdicts = [self._analyze_canon(e) for e in canon]
        tech_seq: list[str] = []
        for v in verdicts:
            for m in v.mitre:
                if not tech_seq or tech_seq[-1] != m:
                    tech_seq.append(m)
        return self.markov.analyze_sequence(tech_seq).to_dict()

    def cluster_sessions(self, sessions: list[dict[str, Any]], eps: float = 0.45,
                         min_samples: int = 2) -> dict[str, Any]:
        """Кластеризация сессий через DBSCAN для выявления распределенных кампаний."""
        clusterer = SessionClusterer(eps=eps, min_samples=min_samples)
        return clusterer.cluster_sessions(sessions)

    def classify_hassh(self, hassh: str, hassh_raw: str = "", client_str: str = "") -> dict[str, Any]:
        """Сигнатурный и эвристический анализ отпечатка HASSH SSH-клиента."""
        from .hassh import classify_hassh
        return classify_hassh(hassh, hassh_raw=hassh_raw, client_str=client_str).to_dict()

    def synthesize_detection_rules(
        self,
        events_or_session: list[Any] | dict[str, Any],
        session_id: str | None = None,
        threat_score: int | None = None,
        category: str | None = None,
    ) -> dict[str, Any]:
        """Синтез правил обнаружения Detection-as-Code (Sigma YAML и YARA) по событиям атаки."""
        from .detection_rules import DetectionRuleSynthesizer
        synth = DetectionRuleSynthesizer()
        return synth.synthesize(
            events_or_session,
            session_id=session_id,
            threat_score=threat_score,
            category=category,
        ).to_dict()

    def generate_report(self, session_or_events: dict[str, Any] | list[Any]) -> dict[str, Any]:
        """Генерация двухконтурного отчета (Executive Brief и Technical DFIR) и матрицы MITRE Engage."""
        from .reports import ReportSynthesizer
        synth = ReportSynthesizer()
        if isinstance(session_or_events, dict):
            return synth.synthesize(session_or_events).to_dict()
        analysis = self.analyze_session(session_or_events)
        return synth.synthesize(analysis).to_dict()


def _download_then_execute(events: list[CanonEvent]) -> bool:
    """В сессии файл сначала скачан (URL/-O/tftp), а позже запущен (./f, sh f, /tmp/f) — разными командами."""
    fetched: set[str] = set()
    for e in events:
        if e.kind != KIND_COMMAND or not e.command:
            continue
        low = e.command.lower()
        for name in list(fetched):
            if re.search(r"(?:\./|\b(?:sh|bash|dash|ash|perl|python\d?)\s+(?:\S*/)?|(?:^|[;&|]\s*)(?:nohup\s+|sudo\s+)?\S*/)"
                         + re.escape(name) + r"(?:\s|;|&|$)", low) \
                    and not _DL_TARGET.search(low):
                return True
        for m in _DL_TARGET.finditer(low):
            name = (m.group(1) or m.group(2) or m.group(3) or "").rsplit("/", 1)[-1]
            if 1 <= len(name) <= 64 and name not in ("-", ".", "..", "index.html"):
                fetched.add(name)
    return False


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
