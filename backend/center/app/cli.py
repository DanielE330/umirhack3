"""CLI: python -m app.cli {gen-key | create-user <логин> [--role admin|operator] | create-admin <логин>}

Пароль спрашивается в терминале; без терминала (скрипт установки) читается одной строкой из stdin.
"""
from __future__ import annotations

import argparse
import getpass
import json
import sys

from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from . import security
from .config import get_settings
from .db import init_db, make_engine
<<<<<<< HEAD
from .honeymind import HoneyMind
from .models import Event, EventLabel, User
from .routers.users import check_password_policy
from .scoring import rescore_events_cli
=======
from .models import User
from .routers.users import _USERNAME, check_password_policy
>>>>>>> origin/dan


def create_user(username: str, role: str = "operator", password: str | None = None) -> None:
    settings = get_settings()
    username = username.strip().lower()
    if not _USERNAME.match(username):
        sys.exit("Логин: 3–64 символа, a-z, 0-9, точка, дефис, подчёркивание")
    engine = make_engine(settings.database_url)
    init_db(engine)
    with sessionmaker(engine)() as db:
        if db.scalar(select(User).where(User.username == username)):
            sys.exit(f"Пользователь {username} уже существует")
        if password is None and not sys.stdin.isatty():
            password = sys.stdin.readline().rstrip("\n")
        if password is None:
            password = getpass.getpass("Пароль: ")
            if getpass.getpass("Повторите пароль: ") != password:
                sys.exit("Пароли не совпадают")
        try:
            check_password_policy(password, username, settings.min_password_length)
        except Exception as exc:  # HTTPException из общей политики паролей
            sys.exit(getattr(exc, "detail", str(exc)))
        db.add(User(username=username, password_hash=security.hash_password(password), role=role))
        db.commit()
    print(f"Пользователь {username} ({role}) создан. 2FA настроится при первом входе.")


def create_admin(username: str, password: str | None = None) -> None:
    create_user(username, "admin", password)


def rescore_cmd(version: str | None = None, batch_size: int = 200) -> None:
    settings = get_settings()
    engine = make_engine(settings.database_url)
    init_db(engine)
    factory = sessionmaker(engine)
    hm = HoneyMind(settings)
    if not hm.url:
        sys.exit("HF_HONEYMIND_URL не настроен в конфигурации")
    count = rescore_events_cli(factory, hm, target_version=version, batch_size=batch_size)
    print(f"Готово. Всего переоценено событий: {count}")


def export_labels_cmd() -> None:
    settings = get_settings()
    engine = make_engine(settings.database_url)
    init_db(engine)
    with sessionmaker(engine)() as db:
        rows = db.execute(
            select(Event.command, EventLabel.label)
            .join(EventLabel, Event.id == EventLabel.event_id)
            .where(Event.type == "command", Event.command.is_not(None))
            .order_by(EventLabel.id.asc())
        ).all()
        for cmd, lbl in rows:
            if cmd:
                print(json.dumps({"command": cmd, "label": lbl}, ensure_ascii=False))


def main() -> None:
    parser = argparse.ArgumentParser(prog="app.cli")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("gen-key")
    cu = sub.add_parser("create-user")
    cu.add_argument("username")
    cu.add_argument("--role", choices=("admin", "operator"), default="operator")
    ca = sub.add_parser("create-admin")
    ca.add_argument("username")

    rc = sub.add_parser("rescore", help="Переоценка событий со старой model_version")
    rc.add_argument("--version", dest="version", default=None, help="Целевая версия модели")
    rc.add_argument("--batch-size", dest="batch_size", type=int, default=200)

    sub.add_parser("export-labels", help="Экспорт меток оператора в формате JSONL для дообучения")

    args = parser.parse_args()
    if args.cmd == "gen-key":
        print(f"HF_SECRET_KEY={security.generate_key()}")
    elif args.cmd == "create-user":
        create_user(args.username, args.role)
    elif args.cmd == "create-admin":
        create_admin(args.username)
    elif args.cmd == "rescore":
        rescore_cmd(version=args.version, batch_size=args.batch_size)
    elif args.cmd == "export-labels":
        export_labels_cmd()


if __name__ == "__main__":
    main()
