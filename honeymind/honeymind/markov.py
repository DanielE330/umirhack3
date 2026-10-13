"""Марковский движок предиктивной аналитики тактических намерений (Markovian Tactical Intent Prediction).

Математический аппарат:
1. Дискретная марковская цепь первого порядка над техниками MITRE ATT&CK:
   P(T_{t+1} = T_j | T_t = T_i)
2. Априорный граф переходов Cyber Kill Chain с регуляризацией Лапласа (alpha = 0.05):
   P(T_j | T_i) = (C(T_i, T_j) + alpha) / sum_k(C(T_i, T_k) + alpha)
3. Информационная энтропия Шеннона для оценки неопределенности следующего шага:
   H(T_i) = - sum_j P(T_j | T_i) * log2(P(T_j | T_i))
4. Индекс тактической девиации (Tactical Deviation Index, TDI):
   Метрика отличия последовательности действий от типовых автоматических ботов.
   TDI < 0.30 -> "scripted" (шаблонный ботнет/скрипт)
   0.30 <= TDI <= 0.65 -> "hybrid" (интерактивный скрипт / смешанное поведение)
   TDI > 0.65 -> "manual_exploratory" (живой оператор / нестандартный APT)
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Iterable


# Каталог ключевых техник MITRE ATT&CK с понятными названиями и тактиками
TECHNIQUES: dict[str, dict[str, str]] = {
    # Discovery
    "T1082": {"name": "System Information Discovery", "tactic": "Discovery", "desc": "Сбор сведений об ОС, архитектуре и ядре"},
    "T1087": {"name": "Account Discovery", "tactic": "Discovery", "desc": "Поиск учетных записей"},
    "T1087.001": {"name": "Local Account Discovery", "tactic": "Discovery", "desc": "Просмотр локальных пользователей и групп"},
    "T1083": {"name": "File and Directory Discovery", "tactic": "Discovery", "desc": "Поиск файлов и каталогов"},
    "T1016": {"name": "System Network Configuration Discovery", "tactic": "Discovery", "desc": "Сбор сетевых настроек и внешнего IP"},
    "T1046": {"name": "Network Service Discovery", "tactic": "Discovery", "desc": "Сканирование портов и сервисов"},
    "T1053.003": {"name": "Scheduled Task / Cron", "tactic": "Discovery", "desc": "Просмотр заданий планировщика cron"},

    # Execution
    "T1059.004": {"name": "Unix Shell Execution", "tactic": "Execution", "desc": "Исполнение команд в командной оболочке"},
    "T1059.006": {"name": "Python Interpreter Execution", "tactic": "Execution", "desc": "Выполнение скриптов через Python"},

    # Privilege Escalation
    "T1548.003": {"name": "Sudo and Sudo Caching", "tactic": "Privilege Escalation", "desc": "Повышение привилегий через sudo"},
    "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation", "desc": "Эксплуатация уязвимостей для получения root"},

    # Defense Evasion
    "T1027": {"name": "Obfuscated/Encoded Files", "tactic": "Defense Evasion", "desc": "Обфускация или кодирование файлов"},
    "T1070.002": {"name": "Clear Linux System Logs", "tactic": "Defense Evasion", "desc": "Удаление системных журналов и utmp/wtmp"},
    "T1070.003": {"name": "Clear Command History", "tactic": "Defense Evasion", "desc": "Отключение или очистка истории bash"},
    "T1070.004": {"name": "File Deletion", "tactic": "Defense Evasion", "desc": "Удаление дропперов и временных файлов"},
    "T1562": {"name": "Impair Defenses", "tactic": "Defense Evasion", "desc": "Остановка защитных процессов и демонов"},
    "T1562.001": {"name": "Disable Security Tools", "tactic": "Defense Evasion", "desc": "Отключение фаерволов, auditd, Wazuh"},
    "T1222.002": {"name": "Linux File Permissions Modification", "tactic": "Defense Evasion", "desc": "Смена прав на исполнение (chmod +x)"},

    # Credential Access
    "T1552.001": {"name": "Credentials In Files", "tactic": "Credential Access", "desc": "Поиск учетных данных в .env, .aws, id_rsa, shadow"},
    "T1552.004": {"name": "Private Keys and Cloud Credentials", "tactic": "Credential Access", "desc": "Поиск приватных SSH-ключей и облачных токенов"},
    "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access", "desc": "Сброс креденшелов из памяти или баз"},
    "T1110": {"name": "Brute Force", "tactic": "Credential Access", "desc": "Перебор учетных данных SSH/FTP/Web"},

    # Persistence
    "T1098": {"name": "Account Manipulation", "tactic": "Persistence", "desc": "Смена паролей существующих пользователей"},
    "T1098.004": {"name": "SSH Authorized Keys", "tactic": "Persistence", "desc": "Добавление публичного ключа в authorized_keys"},
    "T1037.004": {"name": "Boot/Logon Initialization Scripts", "tactic": "Persistence", "desc": "Закрепление в .bashrc, .profile, rc.local"},
    "T1543.002": {"name": "Systemd Service", "tactic": "Persistence", "desc": "Создание и автозапуск вредоносного systemd-сервиса"},
    "T1136.001": {"name": "Create Local Account", "tactic": "Persistence", "desc": "Создание скрытого пользователя (useradd)"},
    "T1574.006": {"name": "Dynamic Linker Hijacking", "tactic": "Persistence", "desc": "Правка ld.so.preload для инъекции руткита"},

    # Command and Control
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "Command and Control", "desc": "Загрузка полезной нагрузки (curl, wget, tftp)"},
    "T1571": {"name": "Reverse Shell / Non-Standard Port", "tactic": "Command and Control", "desc": "Открытие обратного шелла наружу"},

    # Exfiltration
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration", "desc": "Передача конфиденциальных данных на C2-сервер"},

    # Impact
    "T1496": {"name": "Resource Hijacking (Cryptominer)", "tactic": "Impact", "desc": "Майнинг криптовалюты на мощностях хоста"},
    "T1485": {"name": "Data Destruction", "tactic": "Impact", "desc": "Уничтожение файлов или стирание диска"},
    "T1489": {"name": "Service Stop", "tactic": "Impact", "desc": "Принудительная остановка бизнес-сервисов"},
}


# Априорная матрица переходов (Kill Chain Knowledge Graph)
# Задает типовые веса переходов между фазами атак
DEFAULT_TRANSITION_WEIGHTS: dict[str, dict[str, float]] = {
    # Из разведки системы атакующий чаще всего идет за учетными данными, эскалацией прав или скачиванием дроппера
    "T1082": {
        "T1552.001": 8.0,  # поиск секретов и ключей
        "T1548.003": 5.0,  # проверка sudo
        "T1105": 4.5,      # загрузка дроппера
        "T1087.001": 4.0,  # разведка локальных пользователей
        "T1016": 3.0,      # сетевые настройки
        "T1070.003": 1.5,  # подчистить историю
    },
    "T1087": {
        "T1552.001": 7.0,
        "T1548.003": 6.0,
        "T1098.004": 3.5,
        "T1105": 3.0,
    },
    "T1087.001": {
        "T1552.001": 8.0,
        "T1548.003": 6.5,
        "T1098.004": 3.0,
        "T1105": 3.0,
    },
    "T1083": {
        "T1552.001": 8.5,
        "T1222.002": 4.0,
        "T1105": 4.0,
        "T1059.004": 3.5,
    },
    "T1016": {
        "T1046": 6.0,
        "T1105": 5.0,
        "T1552.001": 4.0,
    },
    "T1046": {
        "T1110": 6.0,
        "T1105": 5.0,
        "T1552.001": 4.0,
    },
    # Из кражи креденшелов переход к эксфильтрации, повышению прав или закреплению
    "T1552.001": {
        "T1041": 10.0,     # эксфильтрация украденного
        "T1548.003": 6.0,  # повышение прав
        "T1098.004": 5.0,  # закрепление ключом
        "T1105": 3.0,      # загрузка инструмента
        "T1070.003": 2.5,  # заметание следов
    },
    "T1552.004": {
        "T1041": 10.0,     # эксфильтрация приватных ключей
        "T1548.003": 6.0,  # повышение прав
        "T1098.004": 5.0,  # закрепление ключом
        "T1105": 3.0,      # загрузка инструмента
        "T1070.003": 2.5,  # заметание следов
    },
    "T1003": {
        "T1041": 9.0,
        "T1098.004": 6.0,
        "T1548.003": 5.0,
    },
    # Из загрузки дроппера (T1105) почти всегда следует chmod +x (T1222.002) или прямой запуск (T1059.004)
    "T1105": {
        "T1222.002": 12.0, # chmod +x
        "T1059.004": 8.0,  # запуск скрипта
        "T1070.004": 3.0,  # удаление исходника
        "T1496": 2.5,      # запуск майнера
    },
    # Из смены прав следует исполнение
    "T1222.002": {
        "T1059.004": 14.0,
        "T1053.003": 4.0,
        "T1496": 3.0,
        "T1070.003": 2.0,
    },
    # Из исполнения следует закрепление, майнинг, обратный шелл или заметание следов
    "T1059.004": {
        "T1053.003": 6.0,  # крон
        "T1496": 5.5,      # майнер
        "T1571": 5.0,      # реверс-шелл
        "T1098.004": 4.5,  # ssh-ключ
        "T1070.004": 4.0,  # удаление файлов
        "T1041": 3.0,      # выгрузка
    },
    "T1059.006": {
        "T1571": 7.0,
        "T1041": 5.0,
        "T1070.003": 3.0,
    },
    # Из повышения прав (sudo) переход к закреплению и отключению защиты
    "T1548.003": {
        "T1098.004": 7.0,  # прописать SSH-ключ рута
        "T1562.001": 6.0,  # отключить безопасность
        "T1543.002": 5.0,  # сервис systemd
        "T1552.001": 5.0,  # чтение shadow
        "T1070.002": 4.0,  # чистка логов
    },
    "T1068": {
        "T1098.004": 7.0,
        "T1562.001": 6.0,
        "T1552.001": 5.0,
    },
    # Из закрепления следует заметание следов или завершение
    "T1098.004": {
        "T1070.003": 8.0,  # стереть bash_history
        "T1070.002": 5.0,  # стереть auth.log
        "T1041": 4.0,      # эксфильтрация
    },
    "T1053.003": {
        "T1070.003": 6.0,
        "T1496": 5.0,
        "T1070.004": 4.0,
    },
    "T1543.002": {
        "T1562.001": 6.0,
        "T1070.002": 5.0,
    },
    # Из отключения защиты следует эксфильтрация или исполнение
    "T1562.001": {
        "T1041": 7.0,
        "T1059.004": 6.0,
        "T1496": 5.0,
    },
    "T1070.003": {
        "T1070.002": 7.0,
        "T1041": 5.0,
        "T1082": 3.0,
    },
    "T1070.002": {
        "T1041": 6.0,
        "T1070.004": 5.0,
    },
    "T1070.004": {
        "T1041": 5.0,
        "T1070.003": 4.0,
    },
    # Из реверс-шелла атакующий начинает новую волну разведки под полученным контекстом
    "T1571": {
        "T1082": 8.0,
        "T1548.003": 7.0,
        "T1552.001": 6.0,
    },
    # Из эксфильтрации — финальное заметание следов или деструктивные действия
    "T1041": {
        "T1070.004": 8.0,
        "T1070.002": 6.0,
        "T1485": 4.0,
    },
}


@dataclass
class NextTechniquePrediction:
    technique: str
    name: str
    tactic: str
    probability: float
    description: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique": self.technique,
            "name": self.name,
            "tactic": self.tactic,
            "probability": round(self.probability, 4),
            "description": self.description,
        }


@dataclass
class IntentPredictionResult:
    current_technique: str | None
    current_technique_name: str | None
    current_tactic: str | None
    next_likely_techniques: list[NextTechniquePrediction]
    sequence_entropy: float
    tactical_deviation_index: float
    operator_style: str  # "scripted" | "hybrid" | "manual_exploratory"
    transition_chain: list[str]
    summary_ru: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "current_technique": self.current_technique,
            "current_technique_name": self.current_technique_name,
            "current_tactic": self.current_tactic,
            "next_likely_techniques": [p.to_dict() for p in self.next_likely_techniques],
            "sequence_entropy": round(self.sequence_entropy, 3),
            "tactical_deviation_index": round(self.tactical_deviation_index, 3),
            "operator_style": self.operator_style,
            "transition_chain": self.transition_chain,
            "summary_ru": self.summary_ru,
        }


class MarkovIntentEngine:
    """Марковский движок вероятностного прогнозирования следующей техники атаки и вычисления аномалий."""

    def __init__(self, alpha: float = 0.05, prior_weight: float = 5.0):
        self.alpha = float(alpha)
        self.prior_weight = float(prior_weight)
        self.all_techniques = sorted(list(TECHNIQUES.keys()))
        self.counts: dict[str, dict[str, float]] = {}
        self._init_priors()

    def _init_priors(self) -> None:
        """Инициализация матрицы переходов базовыми весами Kill Chain."""
        for src in self.all_techniques:
            self.counts[src] = {}
            for dst in self.all_techniques:
                self.counts[src][dst] = 0.0

        for src, dsts in DEFAULT_TRANSITION_WEIGHTS.items():
            if src not in self.counts:
                self.counts[src] = {d: 0.0 for d in self.all_techniques}
            for dst, w in dsts.items():
                if dst not in self.counts[src]:
                    self.counts[src][dst] = 0.0
                self.counts[src][dst] += w * self.prior_weight

    def observe_transition(self, from_tech: str, to_tech: str, weight: float = 1.0) -> None:
        """Инкрементальное онлайн-обучение: фиксация реального наблюдаемого перехода в сессии."""
        if from_tech not in self.counts:
            self.counts[from_tech] = {d: 0.0 for d in self.all_techniques}
        if to_tech not in self.counts[from_tech]:
            self.counts[from_tech][to_tech] = 0.0
        self.counts[from_tech][to_tech] += float(weight)

    def observe_sequence(self, sequence: list[str]) -> None:
        """Регистрация цепочки техник из завершенной сессии."""
        cleaned = [t for t in sequence if t in TECHNIQUES or t in self.counts]
        for a, b in zip(cleaned, cleaned[1:]):
            self.observe_transition(a, b)

    def transition_probabilities(self, current_tech: str) -> dict[str, float]:
        """Возвращает распределение вероятностей перехода P(T_j | current_tech) со сглаживанием Лапласа."""
        row = self.counts.get(current_tech, {})
        # Все известные техники, плюс те, что встретились динамически
        candidates = sorted(list(set(self.all_techniques) | set(row.keys())))
        if not candidates:
            return {}

        total_denom = sum(row.get(c, 0.0) + self.alpha for c in candidates)
        probs: dict[str, float] = {}
        for c in candidates:
            numerator = row.get(c, 0.0) + self.alpha
            probs[c] = numerator / total_denom
        return probs

    def predict_next(self, current_tech: str, top_k: int = 3) -> list[NextTechniquePrediction]:
        """Прогнозирует top-K наиболее вероятных следующих техник с описанием и вероятностями."""
        probs = self.transition_probabilities(current_tech)
        if not probs:
            return []

        # Сортируем по убыванию вероятности
        sorted_probs = sorted(probs.items(), key=lambda kv: kv[1], reverse=True)[:top_k]
        results: list[NextTechniquePrediction] = []
        for tech, p in sorted_probs:
            info = TECHNIQUES.get(tech, {"name": tech, "tactic": "Unknown", "desc": "Пользовательская техника"})
            results.append(NextTechniquePrediction(
                technique=tech,
                name=info.get("name", tech),
                tactic=info.get("tactic", "Unknown"),
                probability=p,
                description=info.get("desc", ""),
            ))
        return results

    def calculate_entropy(self, current_tech: str) -> float:
        """Вычисляет нормализованную энтропию Шеннона H(current_tech) в диапазоне [0.0, 1.0]."""
        probs = self.transition_probabilities(current_tech)
        if not probs or len(probs) <= 1:
            return 0.0

        h = 0.0
        for p in probs.values():
            if p > 1e-9:
                h -= p * math.log2(p)

        max_h = math.log2(len(probs))
        return min(1.0, max(0.0, h / max_h)) if max_h > 0 else 0.0

    def analyze_sequence(self, sequence: list[str]) -> IntentPredictionResult:
        """Комплексный анализ цепочки техник сессии:

        - Текущее состояние и прогноз следующего шага
        - Расчет энтропии и Индекса тактической девиации (TDI)
        - Классификация стиля оператора (scripted / hybrid / manual_exploratory)
        """
        # Фильтруем пустые или дублирующиеся подряд техники
        cleaned: list[str] = []
        for t in sequence:
            if t and (not cleaned or cleaned[-1] != t):
                cleaned.append(t)

        if not cleaned:
            return IntentPredictionResult(
                current_technique=None,
                current_technique_name=None,
                current_tactic=None,
                next_likely_techniques=[],
                sequence_entropy=0.0,
                tactical_deviation_index=0.0,
                operator_style="scripted",
                transition_chain=[],
                summary_ru="В сессии пока не зафиксировано специфических техник MITRE ATT&CK.",
            )

        current_tech = cleaned[-1]
        cur_info = TECHNIQUES.get(current_tech, {"name": current_tech, "tactic": "Unknown"})
        next_preds = self.predict_next(current_tech, top_k=3)

        transitions = list(zip(cleaned, cleaned[1:]))
        chain = [f"{a} -> {b}" for a, b in transitions]

        # Вычисляем девиацию переходов (Deviation Score)
        # Для стандартных переходов P(b | a) высока -> штраф девиации низкий
        # Для редких/неожиданных переходов P(b | a) низка -> штраф девиации высокий
        if transitions:
            log_surprises: list[float] = []
            for a, b in transitions:
                p_b = self.transition_probabilities(a).get(b, self.alpha)
                # Ограничиваем нижнюю границу p_b для стабильности логарифма
                p_clamped = max(1e-4, min(1.0, p_b))
                # Неожиданность (Surprisal): -log2(p)
                # Для p=0.4 surprise=1.3; для p=0.001 surprise=10.0
                surprise = -math.log2(p_clamped)
                log_surprises.append(surprise)

            avg_surprise = sum(log_surprises) / len(log_surprises)
            # Нормализуем TDI: surprise от ~1.0 (типовой) до ~10.0 (редкий) -> [0.0, 1.0]
            raw_tdi = (avg_surprise - 1.5) / 6.0
            tdi = max(0.0, min(1.0, raw_tdi))
        else:
            tdi = 0.15  # одиночный начальный шаг

        entropy = self.calculate_entropy(current_tech)

        if tdi < 0.32:
            style = "scripted"
            style_ru = "шаблонизированный бот/скрипт"
        elif tdi <= 0.65:
            style = "hybrid"
            style_ru = "интерактивный инструмент / направленный скрипт"
        else:
            style = "manual_exploratory"
            style_ru = "живой оператор / нестандартная тактика"

        top_pred_str = ""
        if next_preds:
            top_p = next_preds[0]
            top_pred_str = (
                f"С вероятностью {int(top_p.probability * 100)}% следующий шаг — "
                f"{top_p.technique} ({top_p.name}, тактика {top_p.tactic}). "
            )

        summary = (
            f"Текущая техника: {current_tech} ({cur_info.get('name')}). "
            f"{top_pred_str}"
            f"Стиль оператора: {style_ru} (TDI: {tdi:.2f}, энтропия: {entropy:.2f})."
        )

        return IntentPredictionResult(
            current_technique=current_tech,
            current_technique_name=cur_info.get("name"),
            current_tactic=cur_info.get("tactic"),
            next_likely_techniques=next_preds,
            sequence_entropy=entropy,
            tactical_deviation_index=tdi,
            operator_style=style,
            transition_chain=chain,
            summary_ru=summary,
        )
