#!/usr/bin/env python3
"""Обучение модели HoneyMind.

    python train.py                 # LogReg, сохраняет models/honeymind.joblib (+ .sha256)
    python train.py --kind rf       # RandomForest
    python train.py --compare       # групповая кросс-валидация LogReg vs RF (без сохранения)

CV идёт ГРУППАМИ по шаблонам: тестовые команды порождены шаблонами, которых модель в обучении не видела.
Это строже случайного разбиения (где почти-дубликаты утекают в тест), но всё равно на синтетике —
реальную оценку смотрите в evaluate.py.
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import numpy as np
from sklearn.metrics import accuracy_score, f1_score
from sklearn.model_selection import GroupKFold

from honeymind.corpus import build
from honeymind.model import ThreatModel

ROOT = Path(__file__).resolve().parent


def cv_compare(samples, folds: int = 5) -> dict:
    X = np.array([s.text for s in samples], dtype=object)
    y = np.array([s.label for s in samples])
    g = np.array([s.template for s in samples])
    res: dict[str, dict] = {}
    for kind in ("logreg", "rf"):
        accs, f1s = [], []
        t0 = time.time()
        for tr, te in GroupKFold(n_splits=folds).split(X, y, g):
            m = ThreatModel.train(list(X[tr]), list(y[tr]), kind=kind)
            pred = [p.category for p in m.predict_many(list(X[te]))]
            accs.append(accuracy_score(y[te], pred))
            f1s.append(f1_score(y[te], pred, average="macro"))
        res[kind] = {"accuracy_mean": float(np.mean(accs)), "accuracy_std": float(np.std(accs)),
                     "macro_f1_mean": float(np.mean(f1s)), "macro_f1_std": float(np.std(f1s)),
                     "seconds": round(time.time() - t0, 1)}
        print(f"{kind:7s} acc={res[kind]['accuracy_mean']:.3f}±{res[kind]['accuracy_std']:.3f} "
              f"macroF1={res[kind]['macro_f1_mean']:.3f}±{res[kind]['macro_f1_std']:.3f}  ({res[kind]['seconds']}s)")
    return res


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--kind", choices=["logreg", "rf"], default="logreg")
    ap.add_argument("--compare", action="store_true")
    ap.add_argument("--per-template", type=int, default=4)
    ap.add_argument("--out", default=str(ROOT / "models" / "honeymind.joblib"))
    args = ap.parse_args()

    samples = build(per_template=args.per_template)
    labels = sorted({s.label for s in samples})
    print(f"corpus: {len(samples)} samples, {len({s.template for s in samples})} templates, {len(labels)} classes")
    if args.compare:
        res = cv_compare(samples)
        (ROOT / "reports").mkdir(exist_ok=True)
        (ROOT / "reports" / "train_cv.json").write_text(json.dumps(res, indent=2))
        return 0
    model = ThreatModel.train([s.text for s in samples], [s.label for s in samples], kind=args.kind,
                              meta={"corpus_size": len(samples), "classes": labels})
    digest = model.save(args.out)
    print(f"saved {args.out}\nsha256 {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
