#!/usr/bin/env python3
"""Честная оценка HoneyMind на размеченных наборах из data/*.jsonl (поля: command, label, count).

Сравнивает три режима на ОДНИХ И ТЕХ ЖЕ командах:
    rules   — только правила (категория «unknown», если ни одно не сработало)
    model   — только ML (argmax класса, балл = ожидаемая тяжесть)
    hybrid  — как в продакшене

Метрики:
    acc / macroF1   — по классам (macroF1 считается по классам, которые есть в разметке)
    danger P/R/F1   — бинарно «опасно» (истинный класс с severity ≥ 60 против score ≥ 60): то, что реально влияет на алерты
    review          — доля ответов с needs_review (честная «не знаю»)
    acc(w)          — точность, взвешенная частотой команды в реальном трафике
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from sklearn.metrics import f1_score

from honeymind.analyzer import Analyzer
from honeymind.model import ThreatModel
from honeymind.rules import CATEGORIES, DANGER_THRESHOLD

ROOT = Path(__file__).resolve().parent


def load(path: Path) -> list[dict]:
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def run_mode(mode: str, rows: list[dict], model: ThreatModel | None):
    if mode == "rules":
        an = Analyzer(None)
        return [an.analyze_command(r["command"]) for r in rows]
    if mode == "hybrid":
        an = Analyzer(model)
        return [an.analyze_command(r["command"]) for r in rows]
    # model-only: оборачиваем предсказание в Verdict-подобный объект
    class V:  # noqa: D401
        pass
    out = []
    for r in rows:
        p = model.predict(r["command"])
        v = V()
        v.category, v.threat_score, v.needs_review = p.category, int(round(p.expected_score)), p.confidence < 0.55
        out.append(v)
    return out


def metrics(rows, verdicts) -> dict:
    y = [r["label"] for r in rows]
    yp = [v.category for v in verdicts]
    w = [r.get("count", 1) for r in rows]
    n = len(rows)
    acc = sum(a == b for a, b in zip(y, yp)) / n
    accw = sum(wi for a, b, wi in zip(y, yp, w) if a == b) / sum(w)
    labels = sorted(set(y))
    f1 = f1_score(y, yp, labels=labels, average="macro", zero_division=0)
    td = [CATEGORIES[l].severity >= DANGER_THRESHOLD for l in y]
    pd_ = [v.threat_score >= DANGER_THRESHOLD for v in verdicts]
    tp = sum(a and b for a, b in zip(td, pd_)); fp = sum((not a) and b for a, b in zip(td, pd_)); fn = sum(a and (not b) for a, b in zip(td, pd_))
    P = tp / (tp + fp) if tp + fp else float("nan"); R = tp / (tp + fn) if tp + fn else float("nan")
    F = 2 * P * R / (P + R) if (P + R) > 0 else float("nan")
    return {"n": n, "acc": acc, "acc_w": accw, "macro_f1": f1, "danger_P": P, "danger_R": R, "danger_F1": F,
            "tp": tp, "fp": fp, "fn": fn, "review": sum(v.needs_review for v in verdicts) / n}


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% доверительный интервал Уилсона для доли — на 70–150 примерах он широкий, и это надо видеть."""
    if n == 0:
        return float("nan"), float("nan")
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / d
    return c - h, c + h


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("sets", nargs="*", help="jsonl-файлы (по умолчанию все data/eval_*.jsonl)")
    ap.add_argument("--model", default=str(ROOT / "models" / "honeymind.joblib"))
    ap.add_argument("--errors", type=int, default=0, help="показать N ошибок гибрида на набор")
    ap.add_argument("--json", help="сохранить метрики в файл")
    args = ap.parse_args()
    paths = [Path(p) for p in args.sets] or sorted((ROOT / "data").glob("eval_*.jsonl"))
    model = ThreatModel.load(args.model)
    report = {}
    for p in paths:
        rows = load(p)
        print(f"\n=== {p.name}: {len(rows)} уникальных команд, классы: {dict(Counter(r['label'] for r in rows))}")
        print(f"{'mode':7s} {'acc':>6s} {'acc(w)':>7s} {'macroF1':>8s} {'dngP':>6s} {'dngR':>6s} {'dngF1':>6s} {'review':>7s}")
        report[p.name] = {}
        for mode in ("rules", "model", "hybrid"):
            vs = run_mode(mode, rows, model)
            m = metrics(rows, vs)
            report[p.name][mode] = m
            print(f"{mode:7s} {m['acc']:6.3f} {m['acc_w']:7.3f} {m['macro_f1']:8.3f} {m['danger_P']:6.3f} {m['danger_R']:6.3f} {m['danger_F1']:6.3f} {m['review']:7.3f}")
        vs = run_mode("hybrid", rows, model)
        k = sum(r["label"] == v.category for r, v in zip(rows, vs))
        lo, hi = wilson(k, len(rows))
        print(f"hybrid acc {k}/{len(rows)} = {k / len(rows):.3f}, 95% CI Уилсона [{lo:.3f}, {hi:.3f}]")
        by = {}
        for r, v in zip(rows, vs):
            by.setdefault(r.get("sample", "all"), []).append(r["label"] == v.category)
        if len(by) > 1:
            print("по стратам:", ", ".join(f"{k_}: {sum(v_)}/{len(v_)}" for k_, v_ in sorted(by.items())))
        if args.errors:
            bad = [(r, v) for r, v in zip(rows, vs) if r["label"] != v.category]
            print(f"--- ошибки гибрида: {len(bad)} из {len(rows)} (показано {min(args.errors, len(bad))})")
            for r, v in bad[: args.errors]:
                print(f"  истина={r['label']:<20s} предсказано={v.category:<20s} score={v.threat_score:<3d} x{r.get('count', 1):<6} {r['command'][:90]!r}")
    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
