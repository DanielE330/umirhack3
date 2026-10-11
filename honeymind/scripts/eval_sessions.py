"""Проверка is_human на ВАШИХ размеченных сессиях (например, команда сама поиграла в атакующего на honeypot).

    python scripts/eval_sessions.py labeled.jsonl [--model models/human.json]

Формат labeled.jsonl — по сессии в строке:
    {"label": "human" | "bot", "events": [ {строки таблицы: timestamp, event_type, payload, ...}, ... ]}

Печатает вердикт по каждой сессии и сводку. Это единственная по-настоящему честная проверка ветки «человек»:
модель училась на симуляции людей, а здесь — живые люди.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from honeymind.analyzer import Analyzer  # noqa: E402
from honeymind.humanness import HumanModel  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--model", default=str(Path(__file__).resolve().parent.parent / "models" / "human.json"))
    a = ap.parse_args()
    an = Analyzer(None, HumanModel.load(a.model))
    table: Counter = Counter()
    for i, line in enumerate(open(a.path, encoding="utf-8"), 1):
        if not line.strip():
            continue
        o = json.loads(line)
        res = an.analyze_session(o["events"])
        verdict = {True: "human", False: "bot", None: "unknown"}[res["is_human"]]
        table[(o["label"], verdict)] += 1
        print(f"#{i:<3} label={o['label']:<5} → {verdict:<7} p={res['human_probability']}  {res['human_reason']}")
    print("\nистина \\ вердикт   human   bot   unknown")
    for lab in ("human", "bot"):
        print(f"{lab:<18} {table[(lab, 'human')]:>5} {table[(lab, 'bot')]:>5} {table[(lab, 'unknown')]:>9}")


if __name__ == "__main__":
    main()
