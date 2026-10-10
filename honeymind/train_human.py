"""Обучение и проверка модели «человек или бот» (is_human) по сессиям.

    python train_human.py                 # обучить, проверить, сохранить models/human.joblib
    python train_human.py --report reports/human_eval.json

Данные:
  • люди — ТОЛЬКО симуляция (honeymind/simulate.py): в публичных логах людей не нашлось;
  • боты — реальные сессии Cowrie (data/real_bot_sessions.jsonl.gz) + синтетические трудные случаи.
Разбиение реальных ботов на train/test — по СКРИПТУ (один сценарий не попадает в обе части).
Проверка людей — на отдельной симуляции с другим зерном и «сдвинутыми» людьми (быстрые, аккуратные, вставляют
команды из буфера), чтобы видеть, насколько модель держится за то, как именно мы симулировали.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import GroupKFold, cross_val_predict
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from honeymind import simulate
from honeymind.adapter import canonicalize
from honeymind.analyzer import estimate_is_human
from honeymind.adapter import KIND_COMMAND
from honeymind.humanness import FEATURES, HUMAN_MODEL_VERSION, MIN_CMDS_FOR_HUMAN, HumanModel, features

ROOT = Path(__file__).resolve().parent
REAL = ROOT / "data" / "real_bot_sessions.jsonl.gz"
# Реальные сессии, которые при ручном просмотре выглядят как ЛЮДИ (опечатки, исправления, «человеческие» паузы).
# Исключаем их из «ботов» и показываем отдельно. Разметка — один человек (разработчик HoneyMind), по глазам.
SUSPECTED_HUMANS = ROOT / "data" / "real_suspected_humans.json"


def canon(evs):
    return sorted((canonicalize(e) for e in evs), key=lambda e: (e.ts is None, e.ts))


def load_real(include_suspected: bool = False):
    sus = set(json.loads(SUSPECTED_HUMANS.read_text())) if SUSPECTED_HUMANS.exists() else set()
    rows = []
    with gzip.open(REAL, "rt") as f:
        for line in f:
            o = json.loads(line)
            if (o["session"] in sus) != include_suspected:
                continue
            rows.append((canon(o["events"]), o["script"], o["script_total"]))
    return rows


def is_test_script(script: str) -> bool:
    return int(hashlib.sha1(script.encode()).hexdigest(), 16) % 2 == 0


def make_pipe(kind: str) -> Pipeline:
    if kind == "logreg":
        return Pipeline([("sc", StandardScaler()), ("clf", LogisticRegression(C=0.1, max_iter=5000, class_weight="balanced"))])
    return Pipeline([("sc", StandardScaler()), ("clf", HistGradientBoostingClassifier(max_depth=4, learning_rate=0.08,
                                                                                       max_iter=250, random_state=0))])


def n_cmds(ev) -> int:
    return sum(1 for e in ev if e.kind == KIND_COMMAND)


def rates(preds: list, weights: list[float] | None = None) -> dict:
    w = weights or [1.0] * len(preds)
    tot = sum(w) or 1.0
    return {"human": round(sum(x for p, x in zip(preds, w) if p is True) / tot, 4),
            "bot": round(sum(x for p, x in zip(preds, w) if p is False) / tot, 4),
            "unknown": round(sum(x for p, x in zip(preds, w) if p is None) / tot, 4), "n": len(preds)}


class _PipeModel(HumanModel):
    """Обёртка для нелинейной модели (только сравнение в отчёте)."""

    def __init__(self, pipe, meta):  # noqa: D401 — сознательно без вызова родителя
        self.pipe, self.meta = pipe, meta
        self.human_threshold = float(meta.get("human_threshold", 0.9))
        self.bot_threshold = float(meta.get("bot_threshold", 0.3))

    def proba(self, events):
        x = features(events)
        return None if x is None else float(self.pipe.predict_proba(np.array([x]))[0][1])


def _wrap(pipe, kind: str, meta: dict) -> HumanModel:
    return HumanModel.from_pipeline(pipe, meta) if kind == "logreg" else _PipeModel(pipe, meta)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "models" / "human.json"))
    ap.add_argument("--report", default=str(ROOT / "reports" / "human_eval.json"))
    ap.add_argument("--kind", default="logreg", choices=["logreg", "hgb"],
                    help="hgb — только для сравнения в отчёте; сохраняется лишь logreg")
    ap.add_argument("--minimal", type=float, default=0.25,
                    help="доля людей-«минималистов» в обучении (0 — чтобы проверить обобщение на них как на новый тип)")
    a = ap.parse_args()

    # ── данные
    real = load_real()
    real_tr = [r for r in real if not is_test_script(r[1])]
    real_te = [r for r in real if is_test_script(r[1])]
    syn_tr = [(canon(e), y, t) for e, y, t in simulate.build(n_human=2000, n_bot=1500, seed=7, shifted_humans=0.0,
                                                                      minimal_humans=a.minimal)]
    syn_te = [(canon(e), y, t) for e, y, t in simulate.build(n_human=1000, n_bot=1000, seed=99, shifted_humans=0.35, n_hard=300)]

    X, y, groups, src, ncs = [], [], [], [], []
    for ev, lab, typ in syn_tr:
        f = features(ev)
        if f is not None:
            X.append(f); y.append(lab); groups.append(f"syn{len(X)}"); src.append(typ); ncs.append(n_cmds(ev))
    n_syn = len(X)
    for ev, script, _ in real_tr:
        f = features(ev)
        if f is not None:
            X.append(f); y.append(0); groups.append(script); src.append("real_bot"); ncs.append(n_cmds(ev))
    X, y = np.array(X), np.array(y)
    eligible = np.array(ncs) >= MIN_CMDS_FOR_HUMAN  # «человек» возможен только при ≥ 3 командах
    print(f"train: {n_syn} synthetic + {len(X) - n_syn} real-bot sessions; humans={int(y.sum())}")

    # ── порог: по out-of-fold вероятностям на обучении (реальные боты — группами по скрипту)
    oof = cross_val_predict(make_pipe(a.kind), X, y, cv=GroupKFold(n_splits=5), groups=groups, method="predict_proba")[:, 1]
    src_arr = np.array(src)
    grid = [round(t, 2) for t in np.arange(0.5, 0.995, 0.01)]
    rb = (src_arr == "real_bot") & eligible
    sb = (y == 0) & (src_arr != "real_bot") & eligible
    hi = next((t for t in grid if (oof[rb] >= t).mean() == 0 and (oof[sb] >= t).mean() <= 0.005), 0.99)
    lo = 0.3
    print(f"порог «человек» по OOF: {hi}  (ложный «человек» на реальных ботах OOF: {(oof[rb] >= hi).mean():.4f})")

    pipe = make_pipe(a.kind).fit(X, y)
    model = _wrap(pipe, a.kind, {"version": HUMAN_MODEL_VERSION, "kind": a.kind, "human_threshold": hi, "bot_threshold": lo,
                              "features": FEATURES, "n_train": int(len(X)), "n_real_bot_train": int(len(X) - n_syn),
                              "trained_on": "simulated humans + real Cowrie bots (+simulated hard bots)"})

    # ── проверка
    rep: dict = {"kind": a.kind, "human_threshold": hi, "bot_threshold": lo, "minimal_in_train": a.minimal}
    by_type: dict[str, list] = defaultdict(list)
    base_by_type: dict[str, list] = defaultdict(list)
    for ev, lab, typ in syn_te:
        by_type[typ].append(model.decide(ev)[0])
        base_by_type[typ].append(estimate_is_human(ev)[0])
    rep["synthetic_test"] = {t: rates(v) for t, v in sorted(by_type.items())}
    rep["synthetic_test_old_heuristic"] = {t: rates(v) for t, v in sorted(base_by_type.items())}

    rp = [model.decide(ev)[0] for ev, _, _ in real_te]
    rb = [estimate_is_human(ev)[0] for ev, _, _ in real_te]
    w = [float(tot) / sum(1 for r in real_te if r[1] == s) for _, s, tot in real_te]  # вес = сколько реальных сессий представляет
    rep["real_bots_test"] = {"per_sampled_session": rates(rp), "weighted_to_all_sessions": rates(rp, w),
                             "old_heuristic_per_session": rates(rb), "old_heuristic_weighted": rates(rb, w),
                             "n_scripts": len({s for _, s, _ in real_te})}

    # ── как меняется картина при разных порогах «человек»
    sweep = {}
    probs_te = [(typ, model.proba(ev)) for ev, _, typ in syn_te]
    probs_real = [model.proba(ev) for ev, _, _ in real_te]
    for t in (0.5, 0.6, 0.7, 0.8, 0.9, 0.95):
        row = {}
        for typ in sorted({t_ for t_, _ in probs_te}):
            ps = [p for t_, p in probs_te if t_ == typ]
            row[typ] = round(sum(1 for p in ps if p is not None and p >= t) / len(ps), 3)  # без учёта правила ≥3 команд
        row["real_bots"] = round(sum(1 for (ev, _, _), p in zip(real_te, probs_real)
                                     if p is not None and p >= t and n_cmds(ev) >= MIN_CMDS_FOR_HUMAN) / len(probs_real), 4)
        sweep[str(t)] = row
    rep["share_called_human_by_threshold"] = sweep

    # ── абляция: только синтетика (без реальных ботов) → реальные боты. Показывает разрыв «симуляция → реальность».
    pipe_syn = make_pipe(a.kind).fit(X[:n_syn], y[:n_syn])
    m_syn = _wrap(pipe_syn, a.kind, {"human_threshold": hi, "bot_threshold": lo})
    rep["ablation_synthetic_only_on_real_bots"] = rates([m_syn.decide(ev)[0] for ev, _, _ in real_te])
    rep["real_suspected_humans"] = [{"verdict": model.decide(ev)[0], "p_human": round(model.decide(ev)[1] or 0, 3),
                                     "commands": [e.command for e in ev if e.kind == KIND_COMMAND][:12]}
                                    for ev, _, _ in load_real(include_suspected=True)]

    if a.kind == "logreg":
        coef = pipe.named_steps["clf"].coef_[0]
        rep["weights_top"] = [(FEATURES[i], round(float(coef[i]), 2)) for i in np.argsort(-np.abs(coef))[:10]]

    if a.kind == "logreg":
        rep["model_sha256"] = model.save(a.out)
    else:
        print("hgb: отчёт записан, модель НЕ сохраняется (в сервисе используется только logreg)")
    Path(a.report).parent.mkdir(parents=True, exist_ok=True)
    Path(a.report).write_text(json.dumps(rep, ensure_ascii=False, indent=2))
    print(json.dumps(rep, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
