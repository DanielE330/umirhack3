#!/usr/bin/env python3
"""Собирает обучающие данные HoneyMind в явные файлы (чтобы «данные в комплекте с моделью» были файлами, а не только кодом).

    python scripts/build_training_data.py

Пишет:
    data/train/synthetic_corpus.jsonl   развёрнутый синтетический корпус (honeymind/corpus.py): text, label, template
    data/train/real_labeled.jsonl       вручную размеченные РЕАЛЬНЫЕ команды из дампов Cowrie (data/eval_*.jsonl),
                                        без дублей: command, label, count, source

ВАЖНО: real_labeled.jsonl — это те же команды, на которых раньше считались метрики (data/eval_*.jsonl).
Модель, обученная с ними, на этих наборах оценивать нельзя (утечка). Честные цифры — в reports/loro_real_data.json
(leave-one-round-out: обучаем на остальных раундах, проверяем на отложенном) и EVALUATION.md.
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from honeymind.corpus import build  # noqa: E402
from honeymind.rules import CATEGORIES  # noqa: E402


def main() -> int:
    out = ROOT / "data" / "train"
    out.mkdir(parents=True, exist_ok=True)

    synth = build(per_template=4)
    with (out / "synthetic_corpus.jsonl").open("w", encoding="utf-8") as f:
        for s in synth:
            f.write(json.dumps({"text": s.text, "label": s.label, "template": s.template}, ensure_ascii=False) + "\n")

    seen: dict[str, dict] = {}
    conflicts = []
    for p in sorted((ROOT / "data").glob("eval_*.jsonl")):
        for line in p.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            r = json.loads(line)
            if r["label"] not in CATEGORIES:
                raise SystemExit(f"{p.name}: неизвестная метка {r['label']!r}")
            cur = seen.get(r["command"])
            if cur is None:
                seen[r["command"]] = {"command": r["command"], "label": r["label"], "count": r.get("count", 1),
                                      "source": p.stem.removeprefix("eval_")}
            elif cur["label"] != r["label"]:
                conflicts.append((r["command"], cur["label"], r["label"]))
    with (out / "real_labeled.jsonl").open("w", encoding="utf-8") as f:
        for r in seen.values():
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    by = defaultdict(int)
    for r in seen.values():
        by[r["label"]] += 1
    print(f"synthetic_corpus.jsonl: {len(synth)}")
    print(f"real_labeled.jsonl:     {len(seen)} уникальных команд, по классам: {dict(sorted(by.items()))}")
    if conflicts:
        print(f"ВНИМАНИЕ: {len(conflicts)} команд с конфликтующей разметкой (взята первая):")
        for c in conflicts[:10]:
            print("  ", c)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
