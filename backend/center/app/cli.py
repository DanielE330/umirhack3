"""CLI: python -m app.cli {gen-key | create-admin <логин>}"""
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
from .routers.users import check_password_policy


def create_admin(username: str, password: str | None = None) -> None:
    settings = get_settings()
    username = username.strip().lower()
    engine = make_engine(settings.database_url)
    init_db(engine)
    with sessionmaker(engine)() as db:
        if db.scalar(select(User).where(User.username == username)):
            sys.exit(f"Пользователь {username} уже существует")
        if password is None:
            password = getpass.getpass("Пароль: ")
            if getpass.getpass("Повторите пароль: ") != password:
                sys.exit("Пароли не совпадают")
        try:
            check_password_policy(password, username, settings.min_password_length)
        except Exception as exc:  # HTTPException из общей политики паролей
            sys.exit(getattr(exc, "detail", str(exc)))
        db.add(User(username=username, password_hash=security.hash_password(password), role="admin"))
        db.commit()
    print(f"Админ {username} создан. 2FA настроится при первом входе.")


def main() -> None:
    parser = argparse.ArgumentParser(prog="app.cli")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("gen-key")
    ca = sub.add_parser("create-admin")
    ca.add_argument("username")
    args = parser.parse_args()
    if args.cmd == "gen-key":
        print(f"HF_SECRET_KEY={security.generate_key()}")
    else:
        create_admin(args.username)


if __name__ == "__main__":
    main()
