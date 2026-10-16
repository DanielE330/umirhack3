"""Модуль сигнатурного и эвристического анализа отпечатков HASSH (SSH Fingerprinting).

Математический аппарат и спецификация:
1. HASSH — стандарт отпечатков SSH-клиентов (Salesforce, RFC 4253):
   hassh = MD5(kex_algs + ';' + enc_algs_c2s + ';' + mac_algs_c2s + ';' + comp_algs_c2s)
2. Детерминированная классификация источника подключения (Human Terminal vs Automated Botnet/Scanner):
   - Определение инструмента атакующего до исполнения первой команды в шелле.
   - Снижение Alert Fatigue для дежурной смены SOC (фоновый шум ботов не будит оператора).
3. Расчет адаптивного профиля «смоляной ямы» (Adaptive Tarpit Recommendation):
   - Брутфорс и боты -> режим strict (задержка 1.5 - 3.0 с на попытку ввода).
   - Интерактивный терминал человека -> режим adaptive (микропаузы 0.1 - 0.3 с с джиттером для правдоподобности).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


KNOWN_HASSH_DB: dict[str, dict[str, Any]] = {
    # Go-SSH (Mirai, Mozi, автоматические черви и криптомайнеры на Go)
    "817027581fb1a4a44b82d470d0c35478": {
        "client": "Go-SSH / Mirai IoT Botnet",
        "is_human": False,
        "threat_actor": "Automated Worm / Botnet",
        "category": "botnet",
        "risk_level": "high",
        "tarpit_delay_sec": 2.0,
    },
    "b8f74a8d423982cb901b0f1963bb3460": {
        "client": "Golang SSH Scanner (FritzFrog / Mozi)",
        "is_human": False,
        "threat_actor": "Botnet Scanner",
        "category": "botnet",
        "risk_level": "high",
        "tarpit_delay_sec": 2.2,
    },
    # LibSSH / LibSSH2 (Hydra, Nmap, Masscan, Medusa)
    "061d491f618a80bb8b3684a0d9230554": {
        "client": "LibSSH / Hydra Password Brute-forcer",
        "is_human": False,
        "threat_actor": "Brute-force Scanner",
        "category": "bruteforce",
        "risk_level": "high",
        "tarpit_delay_sec": 2.5,
    },
    "60c33efc2ef74f07e5b22b6474b5bc3e": {
        "client": "LibSSH2 Recon Probe / Nmap NSE",
        "is_human": False,
        "threat_actor": "Recon Tool",
        "category": "scanner",
        "risk_level": "medium",
        "tarpit_delay_sec": 1.8,
    },
    # Python Paramiko / AsyncSSH / Twisted
    "ec81a05261d71da0dfa225091b659223": {
        "client": "Python Paramiko / Attacker Script",
        "is_human": False,
        "threat_actor": "Custom Automation Script",
        "category": "script",
        "risk_level": "medium",
        "tarpit_delay_sec": 1.5,
    },
    "8225c2cb911381f1e10f3b612fcbe6a4": {
        "client": "AsyncSSH / Python Automation Framework",
        "is_human": False,
        "threat_actor": "Automation Framework",
        "category": "automation",
        "risk_level": "medium",
        "tarpit_delay_sec": 1.2,
    },
    # JSch (Java-сканеры и эксплойты)
    "79a366b5e054b17904ba88c1c045b41d": {
        "client": "JSch Java Scanner",
        "is_human": False,
        "threat_actor": "Java Automated Probe",
        "category": "scanner",
        "risk_level": "medium",
        "tarpit_delay_sec": 2.0,
    },
    # Phpseclib (PHP веб-шеллы и бэкдоры)
    "8e547dfa7f34c26a27e7f95f4625b1f6": {
        "client": "Phpseclib Web-based Scanner",
        "is_human": False,
        "threat_actor": "Web Shell Scanner",
        "category": "scanner",
        "risk_level": "medium",
        "tarpit_delay_sec": 1.8,
    },

    # ────── Легитимные клиенты человека ──────
    # OpenSSH 8.x / 9.x Client (Ubuntu, Debian, macOS, Arch)
    "553dae556488d0fb06e0018f94ff8890": {
        "client": "OpenSSH 8.x / 9.x Client (Linux/macOS)",
        "is_human": True,
        "threat_actor": "Human Operator Terminal",
        "category": "human_terminal",
        "risk_level": "low",
        "tarpit_delay_sec": 0.2,
    },
    "f75841ff51e6056586043fbcfdd6cff7": {
        "client": "OpenSSH 7.x / 8.x Client",
        "is_human": True,
        "threat_actor": "Human Operator Terminal",
        "category": "human_terminal",
        "risk_level": "low",
        "tarpit_delay_sec": 0.2,
    },
    # PuTTY (Windows)
    "c16428cf1b37c02b703d98bfb8f9e612": {
        "client": "PuTTY Windows Terminal",
        "is_human": True,
        "threat_actor": "Human Operator Terminal",
        "category": "human_terminal",
        "risk_level": "low",
        "tarpit_delay_sec": 0.2,
    },
    # Termius / MobaXterm / SecureCRT
    "37a7be8e1f0629a8a25c1109033320c1": {
        "client": "Termius / MobaXterm Advanced Client",
        "is_human": True,
        "threat_actor": "Human Operator Terminal",
        "category": "human_terminal",
        "risk_level": "low",
        "tarpit_delay_sec": 0.2,
    },
}

_WEAK_CIPHERS_RX = re.compile(r"\b(?:arcfour|blowfish-cbc|3des-cbc|cast128-cbc|diffie-hellman-group1-sha1)\b", re.I)
_BOT_CLIENT_STR_RX = re.compile(r"ssh-2\.0-(?:go\b|libssh|jsch|phpseclib|paramiko|asyncssh|twisted|russh|zgrab|nmap)", re.I)


@dataclass
class HasshAnalysis:
    hassh: str
    matched: bool
    client_name: str
    is_human: bool | None
    category: str
    threat_actor: str
    risk_level: str
    tarpit_mode: str  # "strict" | "adaptive" | "off"
    tarpit_delay_sec: float
    summary_ru: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "hassh": self.hassh,
            "matched": self.matched,
            "client_name": self.client_name,
            "is_human": self.is_human,
            "category": self.category,
            "threat_actor": self.threat_actor,
            "risk_level": self.risk_level,
            "tarpit_mode": self.tarpit_mode,
            "tarpit_delay_sec": round(self.tarpit_delay_sec, 2),
            "summary_ru": self.summary_ru,
        }


def classify_hassh(hassh: str, hassh_raw: str = "", client_str: str = "") -> HasshAnalysis:
    """Выполняет сигнатурный и эвристический анализ отпечатка HASSH."""
    hassh_norm = hassh.strip().lower()

    # 1. Поиск в эталонной базе сигнатур
    if hassh_norm in KNOWN_HASSH_DB:
        info = KNOWN_HASSH_DB[hassh_norm]
        is_human = info["is_human"]
        tarpit_mode = "strict" if not is_human else "adaptive"
        tarpit_delay = float(info["tarpit_delay_sec"])

        actor = info["threat_actor"]
        client = info["client"]
        summary = (
            f"Сигнатурное совпадение HASSH: клиент '{client}' ({actor}). "
            f"Режим тарпита: {tarpit_mode} (задержка {tarpit_delay:.1f} с)."
        )

        return HasshAnalysis(
            hassh=hassh_norm,
            matched=True,
            client_name=client,
            is_human=is_human,
            category=info["category"],
            threat_actor=actor,
            risk_level=info["risk_level"],
            tarpit_mode=tarpit_mode,
            tarpit_delay_sec=tarpit_delay,
            summary_ru=summary,
        )

    # 2. Эвристический анализ при неизвестном хеше
    # Проверка текстовой строки баннера клиента
    if client_str and _BOT_CLIENT_STR_RX.search(client_str):
        return HasshAnalysis(
            hassh=hassh_norm,
            matched=False,
            client_name=f"Automated Library ({client_str})",
            is_human=False,
            category="botnet",
            threat_actor="Automated Scanner",
            risk_level="high",
            tarpit_mode="strict",
            tarpit_delay_sec=2.0,
            summary_ru=f"Неизвестный HASSH ({hassh_norm[:8]}), но баннер '{client_str}' выдает автоматическую библиотеку. Активирован жесткий тарпит.",
        )

    # Проверка набора алгоритмов на архаичные/урезанные шифры ботнетов
    if hassh_raw and _WEAK_CIPHERS_RX.search(hassh_raw):
        return HasshAnalysis(
            hassh=hassh_norm,
            matched=False,
            client_name="Legacy / Lightweight Bot Scanner",
            is_human=False,
            category="legacy_scanner",
            threat_actor="Automated Legacy Probe",
            risk_level="medium",
            tarpit_mode="strict",
            tarpit_delay_sec=1.8,
            summary_ru=f"Неизвестный HASSH ({hassh_norm[:8]}), в предложении шифров найдены устаревшие алгоритмы ботнетов. Активирован тарпит.",
        )

    # Современный неизвестный клиент
    return HasshAnalysis(
        hassh=hassh_norm,
        matched=False,
        client_name="Generic SSH Client",
        is_human=None,  # Недостаточно данных для категоричного вердикта
        category="unknown",
        threat_actor="Unclassified",
        risk_level="low",
        tarpit_mode="adaptive",
        tarpit_delay_sec=0.3,
        summary_ru=f"Новый HASSH ({hassh_norm[:8]}). Назначен адаптивный режим наблюдения.",
    )
