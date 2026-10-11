"""Реальные сессии Cowrie → сессии в формате таблицы бэкенда (для обучения/проверки is_human).

    python scripts/extract_sessions.py OUT.jsonl.gz LOG1.json [LOG2.json.gz ...] [--min-events 4] [--per-script 3]

Берём сессии, где ≥ min-events событий со временем (логины, команды, загрузки). Чтобы один массовый скрипт не
заполонил выборку, от каждого «скелета» последовательности команд берём не больше per-script сессий
(поле "script" хранит этот скелет-хэш — по нему делим train/test, чтобы один и тот же скрипт не попал в обе части).
IP заменяются хэшем (персональные данные не нужны модели).
"""
from __future__ import annotations

import argparse
import collections
import gzip
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from honeymind.humanness import _skeleton  # noqa: E402


def _open(p: str):
    return gzip.open(p, "rt", errors="ignore") if p.endswith(".gz") else open(p, "rt", errors="ignore")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("logs", nargs="+")
    ap.add_argument("--min-events", type=int, default=4)
    ap.add_argument("--per-script", type=int, default=3)
    a = ap.parse_args()

    S: dict[str, list] = collections.defaultdict(list)
    ips: dict[str, str] = {}
    for f in a.logs:
        tag = hashlib.sha1(f.encode()).hexdigest()[:4]
        with _open(f) as fh:
            for line in fh:
                try:
                    o = json.loads(line)
                except ValueError:
                    continue
                sid, e, ts = o.get("session"), o.get("eventid", ""), o.get("timestamp")
                if not sid or not ts:
                    continue
                key = tag + sid
                if e in ("cowrie.login.failed", "cowrie.login.success"):
                    S[key].append((ts, "ssh_login_attempt", {"username": o.get("username"), "password": o.get("password"),
                                                              "success": e.endswith("success")}))
                elif e == "cowrie.command.input":
                    S[key].append((ts, "command_executed", {"command": o.get("input")}))
                elif e == "cowrie.session.file_download":
                    S[key].append((ts, "malware_download", {"url": o.get("url"), "file_hash": o.get("shasum")}))
                else:
                    continue
                ips.setdefault(key, hashlib.sha256(str(o.get("src_ip")).encode()).hexdigest()[:16])

    per_script: collections.Counter = collections.Counter()
    total_scripts: collections.Counter = collections.Counter()
    kept = 0
    with gzip.open(a.out, "wt") as out:
        for key, evs in S.items():
            if len(evs) < a.min_events:
                continue
            evs.sort(key=lambda x: x[0])
            cmds = [p["command"] or "" for _, t, p in evs if t == "command_executed"]
            script = hashlib.sha1("\n".join(_skeleton(c) for c in cmds).encode()).hexdigest()[:16] if cmds \
                else "login:" + ips[key]  # чистый подбор паролей: группируем по атакующему
            total_scripts[script] += 1
            if per_script[script] >= a.per_script:
                continue
            per_script[script] += 1
            rows = [{"id": i + 1, "timestamp": ts, "attacker_ip": ips[key], "event_type": t, "session_id": key, "payload": p}
                    for i, (ts, t, p) in enumerate(evs)]
            out.write(json.dumps({"session": key, "script": script, "script_total": None, "events": rows}) + "\n")
            kept += 1
    # дописываем, сколько всего сессий было у каждого скрипта (полезно для честных метрик «по сессиям»)
    tmp = Path(a.out + ".tmp")
    with gzip.open(a.out, "rt") as src, gzip.open(tmp, "wt") as dst:
        for line in src:
            o = json.loads(line)
            o["script_total"] = total_scripts[o["script"]]
            dst.write(json.dumps(o) + "\n")
    tmp.replace(a.out)
    print(f"sessions ≥{a.min_events} events: {sum(total_scripts.values())}, distinct scripts: {len(total_scripts)}, kept: {kept}")


if __name__ == "__main__":
    main()
