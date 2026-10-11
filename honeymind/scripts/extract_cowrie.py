#!/usr/bin/env python3
"""Конвертер публичных логов Cowrie (cowrie.json / .json.gz, JSON Lines) в формат таблицы HoneyForge:
   id, timestamp, attacker_ip, event_type, payload(JSON)

   event_type: ssh_login_attempt | command_executed | malware_download

Пример:
   python scripts/extract_cowrie.py -o data/ml_dataset_cowrie.csv  cowrie.json  cowrie.json.1.gz
"""
from __future__ import annotations

import argparse
import csv
import gzip
import json
import sys


def open_text(path: str):
    return gzip.open(path, "rt", errors="replace") if path.endswith(".gz") else open(path, "rt", errors="replace")


def convert(obj: dict) -> tuple[str, dict] | None:
    ev = obj.get("eventid")
    if ev in ("cowrie.login.failed", "cowrie.login.success"):
        return "ssh_login_attempt", {"username": obj.get("username"), "password": obj.get("password"),
                                     "success": ev.endswith("success")}
    if ev in ("cowrie.command.input", "cowrie.command.success", "cowrie.command.failed"):
        cmd = obj.get("input") if obj.get("input") is not None else obj.get("command")
        return ("command_executed", {"command": cmd}) if cmd else None
    if ev in ("cowrie.session.file_download", "cowrie.session.file_upload"):
        return "malware_download", {"file_hash": obj.get("shasum"), "url": obj.get("url") or obj.get("outfile")}
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("inputs", nargs="+")
    ap.add_argument("-o", "--output", default="-")
    ap.add_argument("--dedupe-commands", action="store_true", help="оставить по одной строке на уникальную команду")
    args = ap.parse_args()

    out = sys.stdout if args.output == "-" else open(args.output, "w", newline="", encoding="utf-8")
    w = csv.writer(out)
    w.writerow(["id", "timestamp", "attacker_ip", "event_type", "payload"])
    seen: set[str] = set()
    n = bad = 0
    for path in args.inputs:
        with open_text(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except ValueError:
                    bad += 1
                    continue
                if not isinstance(obj, dict):
                    continue
                conv = convert(obj)
                if not conv:
                    continue
                etype, payload = conv
                if args.dedupe_commands and etype == "command_executed":
                    if payload["command"] in seen:
                        continue
                    seen.add(payload["command"])
                n += 1
                w.writerow([n, obj.get("timestamp", ""), obj.get("src_ip", ""), etype,
                            json.dumps(payload, ensure_ascii=False)])
    if out is not sys.stdout:
        out.close()
    print(f"rows={n} skipped_bad_json={bad}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
