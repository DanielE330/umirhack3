"""Модуль автоматического синтеза правил обнаружения Detection-as-Code (Sigma и YARA).

Позволяет SOC-аналитикам и инженерам детекта мгновенно транслировать атаки,
пойманные на ловушке HoneyForge, в машиночитаемые правила защиты для:
1. SIEM-систем (Wazuh, Splunk, Elastic, QRadar, MaxPatrol) — формат Sigma (YAML).
2. EDR и антивирусных сканеров (Kaspersky, CrowdStrike, ClamAV, osquery) — формат YARA (.yar).
"""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

import yaml

from .adapter import KIND_COMMAND, KIND_DOWNLOAD, KIND_HONEYTOKEN, CanonEvent, canonicalize
from .rules import title_ru

_UUID_NAMESPACE = uuid.UUID("3fa85f64-5717-4562-b3fc-2c963f66afa6")

# Регулярные выражения для извлечения индикаторов из команд
_URL_RX = re.compile(r"https?://[^\s;|&'\"]+", re.I)
_IP_PORT_RX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b")
_SCRIPT_EXT_RX = re.compile(r"[\w.\-]+\.(?:sh|py|pl|elf|bin|php|jsp|exe|so)\b", re.I)
_HASH_HEX_RX = re.compile(r"\b[a-fA-F0-9]{32,64}\b")


@dataclass
class ExtractedIOCs:
    commands: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    file_hashes: list[str] = field(default_factory=list)
    script_names: list[str] = field(default_factory=list)
    honeytokens: list[str] = field(default_factory=list)


def extract_iocs_from_events(events: list[CanonEvent]) -> ExtractedIOCs:
    """Извлекает и дедуплицирует все значимые индикаторы компрометации (IoC)."""
    cmds: list[str] = []
    urls: list[str] = []
    hashes: list[str] = []
    scripts: list[str] = []
    tokens: list[str] = []

    seen_cmds: set[str] = set()

    for e in events:
        if e.file_hash and e.file_hash not in hashes:
            hashes.append(e.file_hash.lower())
        if e.url and e.url not in urls:
            urls.append(e.url)
        if e.token_id and e.token_id not in tokens:
            tokens.append(e.token_id)

        if e.kind == KIND_COMMAND and e.command:
            cmd = e.command.strip()
            if cmd and cmd not in seen_cmds:
                seen_cmds.add(cmd)
                cmds.append(cmd)
                for u in _URL_RX.findall(cmd):
                    if u not in urls:
                        urls.append(u)
                for s in _SCRIPT_EXT_RX.findall(cmd):
                    if s not in scripts and s not in ("sh", "bash"):
                        scripts.append(s)
                for h in _HASH_HEX_RX.findall(cmd):
                    if len(h) in (32, 64) and h.lower() not in hashes:
                        hashes.append(h.lower())

        if e.kind == KIND_HONEYTOKEN and e.command and e.command not in tokens:
            tokens.append(e.command.strip())

    return ExtractedIOCs(
        commands=cmds,
        urls=urls,
        file_hashes=hashes,
        script_names=scripts,
        honeytokens=tokens,
    )


def sanitize_yara_identifier(name: str) -> str:
    """Приводит строку к допустимому имени правила YARA ([a-zA-Z0-9_])."""
    clean = re.sub(r"[^a-zA-Z0-9_]", "_", name)
    clean = re.sub(r"_+", "_", clean).strip("_")
    if not clean:
        return "Rule"
    if clean[0].isdigit():
        clean = "Rule_" + clean
    return clean[:64]


def escape_yara_str(val: str) -> str:
    """Экранирует кавычки и обратные слэши для строковых констант YARA."""
    return val.replace("\\", "\\\\").replace('"', '\\"').replace("\r", "").replace("\n", "\\n")


@dataclass
class DetectionRuleBundle:
    session_id: str
    threat_score: int
    category: str
    sigma_yaml: str
    yara_rule: str
    mitre_techniques: list[str]
    iocs_count: dict[str, int]
    generated_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "threat_score": self.threat_score,
            "category": self.category,
            "sigma_yaml": self.sigma_yaml,
            "yara_rule": self.yara_rule,
            "mitre_techniques": self.mitre_techniques,
            "iocs_count": self.iocs_count,
            "generated_at": self.generated_at,
        }


class DetectionRuleSynthesizer:
    """Генератор правил Sigma и YARA на основе данных сессии атаки."""

    def __init__(self, author: str = "HoneyForge Threat Intelligence Engine"):
        self.author = author

    def generate_sigma(
        self,
        session_id: str,
        threat_score: int,
        category: str,
        iocs: ExtractedIOCs,
        mitre_techniques: list[str] | None = None,
    ) -> str:
        """Синтезирует валидное правило Sigma (YAML) по спецификации SigmaHQ."""
        techniques = mitre_techniques or []
        rule_id = str(uuid.uuid5(_UUID_NAMESPACE, f"sigma:{session_id or 'default'}:{category}"))
        now_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        level = "critical" if threat_score >= 85 else ("high" if threat_score >= 60 else "medium")
        title_cat = title_ru(category).capitalize()
        title = f"HoneyForge Auto-Detect: {title_cat} Activity"
        if techniques:
            title += f" ({techniques[0]})"

        # Формирование тегов MITRE ATT&CK
        tags = ["attack.execution"]
        for tech in techniques:
            norm_t = tech.lower().replace(".", "_")
            tag_name = f"attack.{norm_t}"
            if tag_name not in tags:
                tags.append(tag_name)

        # Выделение наиболее характерных паттернов для detection
        selection_patterns: list[str] = []
        for cmd in iocs.commands[:6]:
            # Берем команду целиком или значимую часть, если слишком длинная
            cleaned = cmd.replace("\t", " ").strip()
            if cleaned and cleaned not in selection_patterns:
                selection_patterns.append(cleaned[:120])

        if not selection_patterns and iocs.script_names:
            selection_patterns.extend(iocs.script_names[:4])

        if not selection_patterns:
            selection_patterns = ["/tmp/", "chmod +x"]

        detection_block: dict[str, Any] = {
            "selection_cmd": {
                "CommandLine|contains": selection_patterns,
            },
            "condition": "selection_cmd",
        }

        # Если зафиксирована эксфильтрация или обращение к canary honeytoken
        if iocs.honeytokens:
            detection_block["selection_honeytoken"] = {
                "CommandLine|contains": [t[:80] for t in iocs.honeytokens[:4]],
            }
            detection_block["condition"] = "selection_cmd or selection_honeytoken"

        rule_dict: dict[str, Any] = {
            "title": title,
            "id": rule_id,
            "status": "experimental",
            "description": (
                f"Автоматически синтезировано HoneyForge HoneyMind на основе сессии {session_id or 'live'}. "
                f"Уровень угрозы: {threat_score}/100. Категория: {category}."
            ),
            "references": [
                f"https://attack.mitre.org/techniques/{t.split('.')[0]}/" for t in techniques[:3]
            ] if techniques else ["https://honeyforge.local/alerts"],
            "author": self.author,
            "date": now_date,
            "modified": now_date,
            "tags": tags,
            "logsource": {
                "category": "process_creation",
                "product": "linux",
            },
            "detection": detection_block,
            "falsepositives": [
                "Legitimate administrative maintenance scripts",
                "Automated software deployment pipelines (Ansible/CI-CD)",
            ],
            "level": level,
        }

        return yaml.safe_dump(rule_dict, sort_keys=False, allow_unicode=True)

    def generate_yara(
        self,
        session_id: str,
        threat_score: int,
        category: str,
        iocs: ExtractedIOCs,
        mitre_techniques: list[str] | None = None,
    ) -> str:
        """Синтезирует валидное правило YARA (.yar) для EDR и сканеров."""
        techniques = mitre_techniques or []
        sid_clean = sanitize_yara_identifier(session_id or "live_incident")
        rule_name = f"HoneyForge_Threat_{sid_clean}_{category}"
        now_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        strings_lines: list[str] = []
        str_idx = 1

        # 1. Хеши файлов (SHA-256 / MD5)
        for h in iocs.file_hashes[:4]:
            strings_lines.append(f'        $hash_{str_idx} = "{h}" ascii')
            str_idx += 1

        # 2. Скачиваемые URL и скрипты
        for u in iocs.urls[:4]:
            strings_lines.append(f'        $url_{str_idx} = "{escape_yara_str(u)}" ascii nocase')
            str_idx += 1

        # 3. Характерные строки шелл-команд
        for cmd in iocs.commands[:6]:
            # Пропускаем тривиальные команды вроде "ls", берем содержательные
            if len(cmd) >= 6:
                strings_lines.append(f'        $cmd_{str_idx} = "{escape_yara_str(cmd[:100])}" ascii nocase')
                str_idx += 1

        # 4. Имена скриптов
        for s in iocs.script_names[:4]:
            strings_lines.append(f'        $script_{str_idx} = "{escape_yara_str(s)}" ascii nocase')
            str_idx += 1

        # Запасная сигнатура, если сессия пустая
        if not strings_lines:
            strings_lines.append('        $pattern_default = "chmod +x" ascii nocase')

        # Формирование условия condition
        has_hash = any(line.strip().startswith("$hash_") for line in strings_lines)
        if has_hash and len(strings_lines) > 1:
            condition = "any of ($hash_*) or 1 of ($cmd_*, $url_*, $script_*)"
        else:
            condition = "any of ($*)"

        meta_tech = ", ".join(techniques) if techniques else "Unclassified"

        yara_lines = [
            f"rule {rule_name} {{",
            "    meta:",
            '        description = "Auto-generated detection signature by HoneyForge HoneyMind"',
            f'        author = "{self.author}"',
            f'        date = "{now_date}"',
            f"        threat_score = {threat_score}",
            f'        category = "{category}"',
            f'        mitre_techniques = "{meta_tech}"',
            f'        session_id = "{session_id or "live"}"',
            "    strings:",
            *strings_lines,
            "    condition:",
            f"        {condition}",
            "}",
            "",
        ]

        return "\n".join(yara_lines)

    def synthesize(
        self,
        events_or_session: list[Any] | dict[str, Any],
        session_id: str | None = None,
        threat_score: int | None = None,
        category: str | None = None,
    ) -> DetectionRuleBundle:
        """Главный метод синтеза: принимает список событий или результат analyze_session."""
        now_iso = datetime.now(timezone.utc).isoformat()
        tech_list: list[str] = []

        if isinstance(events_or_session, dict):
            # Передан результат analyze_session или словарь сессии
            sess_dict = events_or_session
            sid = session_id or sess_dict.get("session_id") or "sess_captured"
            score = threat_score if threat_score is not None else int(sess_dict.get("threat_score", 75))
            cat = category or sess_dict.get("category") or "malware_downloader"

            raw_events = sess_dict.get("events", [])
            canon = [canonicalize(e) for e in raw_events] if raw_events else []

            # Если есть команды в виде списка строк
            cmd_list = sess_dict.get("commands", [])
            if cmd_list and not canon:
                canon = [canonicalize({"command": c}) for c in cmd_list]

            # Извлекаем техники
            tech_list = list(sess_dict.get("techniques", []))
            intent = sess_dict.get("intent_prediction", {})
            if intent and isinstance(intent, dict):
                curr = intent.get("current_technique")
                if curr and curr not in tech_list:
                    tech_list.append(curr)
                nxt = intent.get("predicted_technique")
                if nxt and nxt not in tech_list:
                    tech_list.append(nxt)
        else:
            # Передан список событий
            canon = [canonicalize(e) for e in events_or_session]
            sid = session_id or (canon[0].session_id if canon and canon[0].session_id else "sess_captured")
            score = threat_score if threat_score is not None else 80
            cat = category or "credential_access"

        iocs = extract_iocs_from_events(canon)
        sigma = self.generate_sigma(sid, score, cat, iocs, tech_list)
        yara = self.generate_yara(sid, score, cat, iocs, tech_list)

        return DetectionRuleBundle(
            session_id=sid,
            threat_score=score,
            category=cat,
            sigma_yaml=sigma,
            yara_rule=yara,
            mitre_techniques=tech_list,
            iocs_count={
                "commands": len(iocs.commands),
                "urls": len(iocs.urls),
                "file_hashes": len(iocs.file_hashes),
                "scripts": len(iocs.script_names),
                "honeytokens": len(iocs.honeytokens),
            },
            generated_at=now_iso,
        )
