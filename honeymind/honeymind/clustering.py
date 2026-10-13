"""Модуль кластеризации сессий и выявления скоординированных кампаний (Threat Hunting via DBSCAN).

Математический аппарат:
1. Извлечение многомерного вектора «почерка» сессии:
   - TTP (техники MITRE ATT&CK) и категории Kill Chain
   - Лексический профиль команд (нормализованные токены и утилиты)
   - Темповый профиль (медианная скорость ввода, вариация пауз)
   - Цифровой отпечаток клиента (SSH Client / User-Agent)
2. Кастомная взвешенная метрика расстояния в пространстве гетерогенных признаков:
   D(S_i, S_j) = w_ttp * D_ttp + w_cmd * D_cmd + w_timing * D_timing + w_client * D_client
   где D_ttp = 1 - Jaccard(TTP_i, TTP_j),
       D_cmd = 1 - Jaccard(Tokens_i, Tokens_j).
3. Плотная кластеризация DBSCAN (metric='precomputed'):
   - Автоматическое определение числа кампаний без априорного k (в отличие от k-Means).
   - Фильтрация случайного фонового шума (noise label = -1).
   - Объединение распределенных атак с различных IP-адресов в единую скоординированную кампанию.
"""
from __future__ import annotations

import math
import statistics
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable

import numpy as np
from sklearn.cluster import DBSCAN

from .adapter import KIND_COMMAND, KIND_LOGIN, canonicalize
from .markov import TECHNIQUES
from .textnorm import normalize


@dataclass
class SessionProfile:
    session_id: str
    src_ip: str
    commands: list[str]
    command_tokens: set[str]
    techniques: set[str]
    categories: set[str]
    threat_score: int
    ssh_client: str
    timing_median: float
    timing_cv: float
    start_ts: datetime | None = None
    end_ts: datetime | None = None


@dataclass
class CampaignCluster:
    campaign_id: str
    title: str
    sessions_count: int
    unique_ips: list[str]
    session_ids: list[str]
    common_techniques: list[dict[str, str]]
    common_commands: list[str]
    target_tactics: list[str]
    max_threat_score: int
    confidence: float
    recommended_action: str
    summary_ru: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "title": self.title,
            "sessions_count": self.sessions_count,
            "unique_ips": self.unique_ips,
            "session_ids": self.session_ids,
            "common_techniques": self.common_techniques,
            "common_commands": self.common_commands,
            "target_tactics": self.target_tactics,
            "max_threat_score": self.max_threat_score,
            "confidence": float(round(self.confidence, 3)),
            "recommended_action": self.recommended_action,
            "summary_ru": self.summary_ru,
        }


def extract_session_profile(data: dict[str, Any]) -> SessionProfile:
    """Извлекает нормализованный профиль признаков сессии из сырых событий или оценки."""
    session_id = str(data.get("session_id") or data.get("id") or "unknown")
    src_ip = str(data.get("src_ip") or "")
    ssh_client = str(data.get("ssh_client") or "")

    # Извлечение событий
    raw_events = data.get("events") or []
    canon_events = [canonicalize(e) for e in raw_events]
    canon_events.sort(key=lambda e: (e.ts is None, e.ts))

    commands = [str(c) for c in data.get("commands", []) if c]
    if not commands and canon_events:
        commands = [e.command for e in canon_events if e.kind == KIND_COMMAND and e.command]

    tokens: set[str] = set()
    for cmd in commands:
        norm = normalize(cmd).text.lower()
        parts = [p for p in norm.split() if len(p) >= 2]
        tokens.update(parts)

    techniques = set(data.get("techniques") or [])
    categories = set(data.get("categories") or data.get("kill_chain") or [])

    # Если техники не переданы в корне, смотрим verdicts внутри events
    for ev in raw_events:
        if isinstance(ev, dict):
            for m in ev.get("mitre", []):
                techniques.add(m)
            cat = ev.get("category")
            if cat and cat not in ("benign", "unknown"):
                categories.add(cat)

    threat_score = int(data.get("threat_score") or 0)
    if not threat_score and raw_events:
        scores = [int(ev.get("threat_score") or 0) for ev in raw_events if isinstance(ev, dict)]
        threat_score = max(scores, default=0)

    # Анализ темповых интервалов
    ts_list = [e.ts for e in canon_events if e.ts is not None and e.kind in (KIND_COMMAND, KIND_LOGIN)]
    med_gap, cv_gap = 0.0, 0.0
    start_ts = ts_list[0] if ts_list else None
    end_ts = ts_list[-1] if ts_list else None

    if len(ts_list) >= 2:
        gaps = [(b - a).total_seconds() for a, b in zip(ts_list, ts_list[1:]) if (b - a).total_seconds() >= 0]
        if gaps:
            med_gap = float(statistics.median(gaps))
            mean_gap = float(statistics.fmean(gaps))
            if mean_gap > 0 and len(gaps) >= 2:
                cv_gap = float(statistics.pstdev(gaps) / mean_gap)

    return SessionProfile(
        session_id=session_id,
        src_ip=src_ip,
        commands=commands,
        command_tokens=tokens,
        techniques=techniques,
        categories=categories,
        threat_score=threat_score,
        ssh_client=ssh_client,
        timing_median=med_gap,
        timing_cv=cv_gap,
        start_ts=start_ts,
        end_ts=end_ts,
    )


class SessionClusterer:
    """Движок кластеризации сессий DBSCAN для выявления скоординированных кампаний."""

    def __init__(
        self,
        eps: float = 0.45,
        min_samples: int = 2,
        w_ttp: float = 0.40,
        w_cmd: float = 0.35,
        w_timing: float = 0.15,
        w_client: float = 0.10,
    ):
        self.eps = float(eps)
        self.min_samples = int(min_samples)
        self.w_ttp = float(w_ttp)
        self.w_cmd = float(w_cmd)
        self.w_timing = float(w_timing)
        self.w_client = float(w_client)

    def pairwise_distance(self, a: SessionProfile, b: SessionProfile) -> float:
        """Вычисляет дистанцию почерка нарушителя между двумя сессиями D(a, b) in [0.0, 1.0]."""
        if a.session_id == b.session_id:
            return 0.0

        # 1. TTP Distance (Jaccard по техникам и категориям)
        u_tech = a.techniques | b.techniques
        if u_tech:
            d_ttp = 1.0 - (len(a.techniques & b.techniques) / len(u_tech))
        else:
            u_cat = a.categories | b.categories
            d_ttp = 1.0 - (len(a.categories & b.categories) / len(u_cat)) if u_cat else 0.5

        # 2. Command Tokens Distance (Jaccard по токенам команд)
        u_tokens = a.command_tokens | b.command_tokens
        if u_tokens:
            d_cmd = 1.0 - (len(a.command_tokens & b.command_tokens) / len(u_tokens))
        else:
            d_cmd = 0.0 if not a.commands and not b.commands else 0.5

        # 3. Timing Distance
        if a.timing_median > 0 and b.timing_median > 0:
            denom_med = max(a.timing_median, b.timing_median, 1.0)
            diff_med = abs(a.timing_median - b.timing_median) / denom_med
            denom_cv = max(a.timing_cv, b.timing_cv, 1.0)
            diff_cv = abs(a.timing_cv - b.timing_cv) / denom_cv
            d_timing = min(1.0, 0.5 * diff_med + 0.5 * diff_cv)
        else:
            d_timing = 0.25  # нейтральное расстояние при отсутствии таймингов

        # 4. Client Fingerprint Penalty
        if a.ssh_client and b.ssh_client:
            d_client = 0.0 if a.ssh_client.lower() == b.ssh_client.lower() else 0.8
        else:
            d_client = 0.2

        total = (self.w_ttp * d_ttp) + (self.w_cmd * d_cmd) + (self.w_timing * d_timing) + (self.w_client * d_client)
        return float(min(1.0, max(0.0, total)))

    def cluster_sessions(self, raw_sessions: list[dict[str, Any]]) -> dict[str, Any]:
        """Кластеризует список сессий и возвращает обнаруженные скоординированные кампании."""
        if not raw_sessions:
            return {
                "campaigns": [],
                "noise_sessions_count": 0,
                "noise_session_ids": [],
                "total_sessions": 0,
            }

        profiles = [extract_session_profile(s) for s in raw_sessions]
        n = len(profiles)

        # Если сессий меньше min_samples, они все считаются некоррелированным шумом
        if n < self.min_samples:
            return {
                "campaigns": [],
                "noise_sessions_count": n,
                "noise_session_ids": [p.session_id for p in profiles],
                "total_sessions": n,
            }

        # Строим матрицу попарных расстояний
        dist_matrix = np.zeros((n, n), dtype=np.float64)
        for i in range(n):
            for j in range(i + 1, n):
                d = self.pairwise_distance(profiles[i], profiles[j])
                dist_matrix[i, j] = d
                dist_matrix[j, i] = d

        # Запускаем DBSCAN
        db = DBSCAN(metric="precomputed", eps=self.eps, min_samples=self.min_samples)
        labels = db.fit_predict(dist_matrix)

        # Группируем сессии по кластерам
        clusters_map: dict[int, list[SessionProfile]] = {}
        noise_ids: list[str] = []

        for idx, label in enumerate(labels):
            if label == -1:
                noise_ids.append(profiles[idx].session_id)
            else:
                clusters_map.setdefault(label, []).append(profiles[idx])

        campaigns: list[CampaignCluster] = []
        for c_idx, (label, c_profiles) in enumerate(sorted(clusters_map.items()), start=1):
            unique_ips = sorted(list({p.src_ip for p in c_profiles if p.src_ip}))
            session_ids = [p.session_id for p in c_profiles]

            # Агрегация техник
            tech_counts: dict[str, int] = {}
            for p in c_profiles:
                for t in p.techniques:
                    tech_counts[t] = tech_counts.get(t, 0) + 1

            sorted_techs = sorted(tech_counts.items(), key=lambda kv: kv[1], reverse=True)
            tech_dicts: list[dict[str, str]] = []
            tactics: set[str] = set()

            for t, _ in sorted_techs:
                info = TECHNIQUES.get(t, {"name": t, "tactic": "Unknown"})
                tech_dicts.append({"technique": t, "name": info.get("name", t), "tactic": info.get("tactic", "Unknown")})
                if info.get("tactic") and info.get("tactic") != "Unknown":
                    tactics.add(info["tactic"])

            # Агрегация общих команд
            cmd_counts: dict[str, int] = {}
            for p in c_profiles:
                for c in p.commands:
                    cmd_counts[c] = cmd_counts.get(c, 0) + 1
            sorted_cmds = [cmd for cmd, count in sorted(cmd_counts.items(), key=lambda kv: kv[1], reverse=True) if count >= 2][:5]
            if not sorted_cmds and c_profiles[0].commands:
                sorted_cmds = c_profiles[0].commands[:3]

            max_score = max(p.threat_score for p in c_profiles)

            # Вычисляем силу связности внутри кластера (внутрикластерную плотность)
            cluster_indices = [idx for idx, l in enumerate(labels) if l == label]
            sub_dists = [dist_matrix[i, j] for i in cluster_indices for j in cluster_indices if i < j]
            avg_sub_dist = sum(sub_dists) / len(sub_dists) if sub_dists else 0.0
            confidence = max(0.5, 1.0 - avg_sub_dist)

            # Формирование заголовка и сводки
            primary_tactic = list(tactics)[0] if tactics else "Active Reconnaissance"
            primary_tech = tech_dicts[0]["name"] if tech_dicts else "Command Probing"
            title = f"Campaign #{c_idx}: {primary_tactic} ({primary_tech})"

            # Рекомендация для SOC
            ips_str = ", ".join(unique_ips[:4]) + ("..." if len(unique_ips) > 4 else "")
            if max_score >= 90:
                rec_action = f"Критический инцидент: немедленно блокировать выявленный пул адресов ({ips_str}), провести аудит учетных данных и изолировать скомпрометированные узлы."
            elif max_score >= 60:
                rec_action = f"Внести IP-адреса ({ips_str}) в черный список периметра, проверить журналы на предмет утечки ключей."
            else:
                rec_action = f"Добавить адреса ({ips_str}) в список повышенного внимания (Watchlist)."

            summary_ru = (
                f"Выявлена скоординированная кампания #{c_idx}: {len(c_profiles)} атак с "
                f"{len(unique_ips)} различных IP-адресов. "
                f"Ключевые техники: {', '.join(t['technique'] for t in tech_dicts[:3]) if tech_dicts else 'системные пробы'}. "
                f"Максимальный риск: {max_score}/100. Уверенность кластеризации: {confidence:.0%}."
            )

            campaigns.append(CampaignCluster(
                campaign_id=f"campaign-{c_idx}",
                title=title,
                sessions_count=len(c_profiles),
                unique_ips=unique_ips,
                session_ids=session_ids,
                common_techniques=tech_dicts,
                common_commands=sorted_cmds,
                target_tactics=sorted(list(tactics)),
                max_threat_score=max_score,
                confidence=confidence,
                recommended_action=rec_action,
                summary_ru=summary_ru,
            ))

        return {
            "campaigns": [c.to_dict() for c in campaigns],
            "noise_sessions_count": len(noise_ids),
            "noise_session_ids": noise_ids,
            "total_sessions": n,
        }
