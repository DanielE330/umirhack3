"""CLI: python -m app.cli {gen-key | create-user <логин> [--role admin|operator] | create-admin <логин>}

Пароль спрашивается в терминале; без терминала (скрипт установки) читается одной строкой из stdin.
"""
from __future__ import annotations

import argparse
import getpass
import sys

from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from . import security
from .config import get_settings
from .db import init_db, make_engine
from .models import User
from .routers.users import _USERNAME, check_password_policy


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


def main() -> None:
    parser = argparse.ArgumentParser(prog="app.cli")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("gen-key")
    cu = sub.add_parser("create-user")
    cu.add_argument("username")
    cu.add_argument("--role", default="operator", help="admin, operator, analyst, deployer, auditor, viewer или своя роль")
    ca = sub.add_parser("create-admin")
    ca.add_argument("username")
    args = parser.parse_args()
    if args.cmd == "gen-key":
        print(f"HF_SECRET_KEY={security.generate_key()}")
    elif args.cmd == "create-user":
        create_user(args.username, args.role)
    else:
        create_admin(args.username)


if __name__ == "__main__":
    main()
