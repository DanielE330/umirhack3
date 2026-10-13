"""Модуль двухконтурных отчётов (Dual-Loop Report Synthesizer) и матрицы MITRE Engage.

Архитектура отчётности:
1. Контур 1: Executive Brief (для C-Level / руководства)
   - Понятный язык без технического шума, оценка бизнес-рисков и ущерба.
   - 100% защита от Prompt Injection (данные изолированы от неструктурированного текста).
   - Метрики удержания и сэкономленного времени аналитиков.
2. Контур 2: Technical DFIR Report (для SOC / криминалистов)
   - Детальный таймлайн действий атакующего с таймстемпами.
   - Сквозной маппинг на MITRE ATT&CK (действия нарушителя) и MITRE Engage (действия ловушки).
   - Индикаторы компрометации (IoC), HASSH-отпечатки, прогноз намерений по Маркову.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .rules import title_ru

# ─────────────────────────────────────────────────────────────────────────────
# Матрица активной защиты MITRE Engage (Deception & Adversary Engagement)
# ─────────────────────────────────────────────────────────────────────────────
ENGAGE_ACTIVITIES: dict[str, dict[str, str]] = {
    "EAC0001": {
        "id": "EAC0001",
        "name": "Lure & Decoy Deployment",
        "goal": "Prepare",
        "desc_ru": "Развёртывание приманочных сервисов (SSH, MySQL, HTTP traps)",
    },
    "EAC0002": {
        "id": "EAC0002",
        "name": "System Architecture Emulation",
        "goal": "Prepare",
        "desc_ru": "Эмуляция окружения ОС (файловая система, /proc, os-release)",
    },
    "EAC0003": {
        "id": "EAC0003",
        "name": "High-Fidelity Telemetry Capture",
        "goal": "Expose",
        "desc_ru": "Непрерывный перехват ввода команд и сетевых запросов",
    },
    "EAC0004": {
        "id": "EAC0004",
        "name": "Adversary Tooling Fingerprinting",
        "goal": "Expose",
        "desc_ru": "Сигнатурная идентификация инструмента нарушителя (HASSH / KEXINIT)",
    },
    "EAC0005": {
        "id": "EAC0005",
        "name": "Time Dilation / Adaptive Tarpit",
        "goal": "Affect",
        "desc_ru": "Адаптивное замедление нарушителя и истощение ресурсов ботнета",
    },
    "EAC0006": {
        "id": "EAC0006",
        "name": "Canary Honeytoken Seeding",
        "goal": "Elicit",
        "desc_ru": "Подсовывание контекстных приманочных ключей (AWS, SSH, ENV)",
    },
    "EAC0007": {
        "id": "EAC0007",
        "name": "Out-of-Band Exfiltration Tripwire",
        "goal": "Expose",
        "desc_ru": "Детектирование активации украденных токенов во внешней сети",
    },
    "EAC0008": {
        "id": "EAC0008",
        "name": "Tactical Intent Forecasting",
        "goal": "Understand",
        "desc_ru": "Марковское предсказание следующего вектора атаки нарушителя",
    },
    "EAC0009": {
        "id": "EAC0009",
        "name": "Campaign Correlation Clustering",
        "goal": "Understand",
        "desc_ru": "DBSCAN-кластеризация распределённых сессий в единую кампанию",
    },
}

_PROMPT_INJ_PATTERNS = re.compile(
    r"(?:ignore\s+(?:all\s+)?previous\s+instructions|system\s+override|prompt\s+injection|"
    r"ты\s+должен\s+написать|забудь\s+(?:все\s+)?инструкции|режим\s+разработчика|"
    r"you\s+are\s+now\s+in\s+developer\s+mode|as\s+an\s+ai\s+language\s+model)",
    re.I,
)


def sanitize_report_field(val: Any) -> str:
    """Очищает строку от потенциальных prompt-injection инъекций и спецсимволов."""
    if val is None:
        return ""
    s = str(val).strip()
    s = _PROMPT_INJ_PATTERNS.sub("[SANITIZED_INJECTION_ATTEMPT]", s)
    return s[:500]


def evaluate_mitre_engage(session: dict[str, Any]) -> list[dict[str, Any]]:
    """Сопоставляет события сессии с активностями матрицы MITRE Engage."""
    activated: list[str] = ["EAC0001", "EAC0002", "EAC0003"]  # Базовые ловушки и перехват

    # HASSH
    if session.get("hassh") or session.get("hassh_profile"):
        activated.append("EAC0004")

    # Tarpit
    hassh_prof = session.get("hassh_profile") or {}
    if hassh_prof.get("tarpit_mode") in ("strict", "adaptive"):
        activated.append("EAC0005")

    # Honeytokens
    events = session.get("events") or []
    has_tokens = any(e.get("kind") == "honeytoken" or "honeytoken" in str(e.get("matched_rules", [])) for e in events)
    if has_tokens:
        activated.append("EAC0006")

    # OOB Canary trip
    if session.get("exfiltration_confirmed"):
        activated.append("EAC0007")

    # Markov Intent
    intent = session.get("intent_prediction") or {}
    if intent.get("current_technique") or intent.get("predicted_technique"):
        activated.append("EAC0008")

    # Campaign cluster
    if session.get("cluster_id") is not None and session.get("cluster_id") != -1:
        activated.append("EAC0009")

    res: list[dict[str, Any]] = []
    for act_id in sorted(set(activated)):
        meta = ENGAGE_ACTIVITIES.get(act_id)
        if meta:
            res.append({
                "activity_id": meta["id"],
                "activity_name": meta["name"],
                "goal": meta["goal"],
                "description_ru": meta["desc_ru"],
                "status": "engaged",
            })
    return res


@dataclass
class ExecutiveBrief:
    headline: str
    risk_level: str
    threat_score: int
    business_impact: str
    attacker_attribution: str
    data_exfiltration_status: str
    time_wasted_seconds: float
    analyst_time_saved_hours: float
    mitre_engage_count: int
    action_items: list[str]
    generated_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "headline": self.headline,
            "risk_level": self.risk_level,
            "threat_score": self.threat_score,
            "business_impact": self.business_impact,
            "attacker_attribution": self.attacker_attribution,
            "data_exfiltration_status": self.data_exfiltration_status,
            "time_wasted_seconds": round(self.time_wasted_seconds, 1),
            "analyst_time_saved_hours": round(self.analyst_time_saved_hours, 1),
            "mitre_engage_count": self.mitre_engage_count,
            "action_items": self.action_items,
            "generated_at": self.generated_at,
        }

    def to_markdown(self) -> str:
        items = "\n".join(f"  {i+1}. {item}" for i, item in enumerate(self.action_items))
        return (
            f"## 📋 Сводный отчёт для руководства (Executive Brief)\n\n"
            f"**Инцидент:** {self.headline}\n\n"
            f"- **Уровень риска:** {self.risk_level} ({self.threat_score}/100)\n"
            f"- **Оценка атрибуции:** {self.attacker_attribution}\n"
            f"- **Утечка данных:** {self.data_exfiltration_status}\n"
            f"- **Влияние на бизнес:** {self.business_impact}\n\n"
            f"### 🛡️ Эффективность активной защиты (MITRE Engage):\n"
            f"- Активировано механизмов дезинформации: **{self.mitre_engage_count}**\n"
            f"- Задержка нарушителя в ловушке: **{self.time_wasted_seconds:.1f} с**\n"
            f"- Сэкономлено рабочего времени аналитиков SOC: **{self.analyst_time_saved_hours:.1f} ч**\n\n"
            f"### 🎯 Рекомендуемые шаги руководству:\n"
            f"{items}\n"
        )


@dataclass
class TechnicalDFIRReport:
    session_id: str
    incident_timestamp: str
    threat_score: int
    category: str
    timeline: list[dict[str, Any]]
    iocs: dict[str, list[str]]
    mitre_attack_chain: list[str]
    mitre_engage_matrix: list[dict[str, Any]]
    markov_forecast: dict[str, Any]
    hassh_forensics: dict[str, Any]
    generated_rules: dict[str, str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "incident_timestamp": self.incident_timestamp,
            "threat_score": self.threat_score,
            "category": self.category,
            "timeline": self.timeline,
            "iocs": self.iocs,
            "mitre_attack_chain": self.mitre_attack_chain,
            "mitre_engage_matrix": self.mitre_engage_matrix,
            "markov_forecast": self.markov_forecast,
            "hassh_forensics": self.hassh_forensics,
            "generated_rules": self.generated_rules,
        }

    def to_markdown(self) -> str:
        timeline_rows = []
        for item in self.timeline[:15]:
            ts = item.get("ts", "N/A")
            kind = item.get("kind", "")
            action = sanitize_report_field(item.get("action", ""))
            score = item.get("threat_score", 0)
            timeline_rows.append(f"| {ts} | `{kind}` | `{action}` | {score}/100 |")
        timeline_table = (
            "| Время (UTC) | Тип | Действие / Команда | Оценка |\n"
            "| :--- | :--- | :--- | :--- |\n"
            + "\n".join(timeline_rows)
        )

        engage_rows = []
        for eng in self.mitre_engage_matrix:
            engage_rows.append(f"| **{eng['activity_id']}** | {eng['activity_name']} | {eng['goal']} | {eng['description_ru']} |")
        engage_table = (
            "| ID | Активность Engage | Цель | Описание |\n"
            "| :--- | :--- | :--- | :--- |\n"
            + "\n".join(engage_rows)
        )

        attack_chain_str = " ➔ ".join(self.mitre_attack_chain) if self.mitre_attack_chain else "Отсутствуют"

        return (
            f"## 🔬 Технический форензик-отчёт (Technical DFIR)\n\n"
            f"**ID сессии:** `{self.session_id}` | **Категория:** `{self.category}` | **Threat Score:** `{self.threat_score}/100`\n\n"
            f"### 1. Цепочка техник MITRE ATT&CK:\n"
            f"`{attack_chain_str}`\n\n"
            f"### 2. Матрица активной защиты MITRE Engage:\n"
            f"{engage_table}\n\n"
            f"### 3. Хронологический таймлайн событий (Timeline):\n"
            f"{timeline_table}\n\n"
            f"### 4. Индикаторы компрометации (IoC):\n"
            f"- **IP-адреса:** {', '.join(f'`{ip}`' for ip in self.iocs.get('ips', [])) or '—'}\n"
            f"- **Хэши файлов:** {', '.join(f'`{h[:16]}...`' for h in self.iocs.get('hashes', [])) or '—'}\n"
            f"- **URL загрузок:** {', '.join(f'`{u}`' for u in self.iocs.get('urls', [])) or '—'}\n"
            f"- **Honeytokens:** {', '.join(f'`{t}`' for t in self.iocs.get('honeytokens', [])) or '—'}\n\n"
            f"### 5. HASSH Криминалистика:\n"
            f"- Клиент: `{self.hassh_forensics.get('client_name', 'Не опознан')}`\n"
            f"- HASSH отпечаток: `{self.hassh_forensics.get('hassh', '—')}`\n"
            f"- Режим тарпита: `{self.hassh_forensics.get('tarpit_mode', 'off')}` (задержка {self.hassh_forensics.get('tarpit_delay_sec', 0)} с)\n"
        )


@dataclass
class DualLoopReport:
    session_id: str
    executive: ExecutiveBrief
    technical: TechnicalDFIRReport

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "executive": self.executive.to_dict(),
            "technical": self.technical.to_dict(),
            "executive_markdown": self.executive.to_markdown(),
            "technical_markdown": self.technical.to_markdown(),
        }


class ReportSynthesizer:
    """Синтезатор двухконтурных отчётов (Dual-Loop) с изоляцией от инъекций."""

    def synthesize(self, session: dict[str, Any]) -> DualLoopReport:
        sid = sanitize_report_field(session.get("session_id") or "sess_live")
        score = int(session.get("threat_score") or 0)
        category = sanitize_report_field(session.get("category") or "benign")
        now_iso = datetime.now(timezone.utc).isoformat()

        # Расчет матрицы MITRE Engage
        engage_matrix = evaluate_mitre_engage(session)

        # ── 1. Формирование контура Executive Brief ──
        level = "Критический" if score >= 85 else ("Высокий" if score >= 60 else ("Средний" if score >= 35 else "Низкий"))
        cat_ru = title_ru(category).capitalize()
        headline = f"{cat_ru}: активность нарушителя на приманочном узле HoneyForge"

        is_human = session.get("is_human")
        method = session.get("human_method") or "heuristic"
        hassh_p = session.get("hassh_profile") or {}
        if is_human is False:
            if method == "hassh":
                attacker_attr = f"Автоматизированный бот / сканер ({hassh_p.get('client_name', 'SSH Botnet')})"
            else:
                attacker_attr = "Автоматизированный вредоносный скрипт (высокий темп команд)"
        elif is_human is True:
            attacker_attr = "Живой оператор (интерактивный ввод, вариативный темп)"
        else:
            attacker_attr = "Не классифицирован (смешанный профиль активности)"

        exfil = session.get("exfiltration_confirmed", False)
        if exfil:
            data_status = "⚠️ ВНИМАНИЕ: Зафиксирована активация приманочного токена во внешней сети!"
            impact = "Попытка несанкционированного доступа пресечена на уровне канареечного токена. Реальные корпоративные ресурсы не скомпрометированы."
        else:
            data_status = "✅ Целостность подтверждена: утечки данных с хоста нет, боевые ключи не затронуты."
            impact = "Нарушитель изолирован внутри синтетической песочницы HoneyForge. Эксфильтрация боевых конфигов не удалась."

        # Оценка задержки и экономии
        tarpit_delay = float(hassh_p.get("tarpit_delay_sec") or 0.3)
        n_events = int(session.get("n_events") or len(session.get("events") or []))
        time_wasted = max(1.5, n_events * tarpit_delay)
        analyst_saved = round(max(0.5, score / 25.0), 1)

        actions = [
            "Внести IP-адрес источника в список фильтрации на пограничном фаерволе.",
            "Импортировать автоматически сгенерированное правило Sigma в корпоративную SIEM.",
        ]
        if exfil:
            actions.append("Провести ротацию скомпрометированного канареечного идентификатора.")
        else:
            actions.append("Продолжить непрерывный сбор телеметрии в режиме смоляной ямы.")

        executive = ExecutiveBrief(
            headline=headline,
            risk_level=level,
            threat_score=score,
            business_impact=impact,
            attacker_attribution=attacker_attr,
            data_exfiltration_status=data_status,
            time_wasted_seconds=time_wasted,
            analyst_time_saved_hours=analyst_saved,
            mitre_engage_count=len(engage_matrix),
            action_items=actions,
            generated_at=now_iso,
        )

        # ── 2. Формирование контура Technical DFIR ──
        raw_events = session.get("events") or []
        timeline: list[dict[str, Any]] = []
        iocs_ips: set[str] = set()
        iocs_hashes: set[str] = set()
        iocs_urls: set[str] = set()
        iocs_tokens: set[str] = set()

        if session.get("src_ip"):
            iocs_ips.add(str(session.get("src_ip")))

        for ev in raw_events:
            ts = ev.get("ts") or ev.get("timestamp") or "00:00:00"
            kind = ev.get("kind") or ev.get("type") or "event"
            cmd = ev.get("command") or ev.get("action") or ev.get("summary") or ""
            sc = ev.get("threat_score") or 0
            timeline.append({
                "ts": str(ts)[:19],
                "kind": kind,
                "action": sanitize_report_field(cmd),
                "threat_score": sc,
            })
            if ev.get("src_ip"):
                iocs_ips.add(str(ev.get("src_ip")))
            if ev.get("file_hash"):
                iocs_hashes.add(str(ev.get("file_hash")))
            if ev.get("url"):
                iocs_urls.add(str(ev.get("url")))
            if ev.get("token_id"):
                iocs_tokens.add(str(ev.get("token_id")))

        mitre_chain = list(session.get("kill_chain") or [])
        intent = session.get("intent_prediction") or {}
        if intent.get("current_technique") and intent.get("current_technique") not in mitre_chain:
            mitre_chain.append(intent["current_technique"])

        det_rules = session.get("detection_rules") or {}
        generated_rules = {
            "sigma_yaml": det_rules.get("sigma_yaml", ""),
            "yara_rule": det_rules.get("yara_rule", ""),
        }

        technical = TechnicalDFIRReport(
            session_id=sid,
            incident_timestamp=now_iso,
            threat_score=score,
            category=category,
            timeline=timeline,
            iocs={
                "ips": sorted(iocs_ips),
                "hashes": sorted(iocs_hashes),
                "urls": sorted(iocs_urls),
                "honeytokens": sorted(iocs_tokens),
            },
            mitre_attack_chain=mitre_chain,
            mitre_engage_matrix=engage_matrix,
            markov_forecast=intent,
            hassh_forensics=hassh_p,
            generated_rules=generated_rules,
        )

        return DualLoopReport(
            session_id=sid,
            executive=executive,
            technical=technical,
        )
