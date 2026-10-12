from __future__ import annotations

from collections.abc import Iterator

from fastapi import Request
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from .models import Base, Role


def make_engine(url: str) -> Engine:
    if url.startswith("sqlite"):
        kwargs: dict = {"connect_args": {"check_same_thread": False}}
        if ":memory:" in url or url.endswith("://"):
            kwargs["poolclass"] = StaticPool
        return create_engine(url, **kwargs)
    return create_engine(url, pool_pre_ping=True)


# Колонки, добавленные после первого релиза: create_all не меняет существующие таблицы
LATE_COLUMNS = {
    "traps": {"machine_vmid": "INTEGER"},
    "events": {
        "threat_score": "INTEGER",
        "category": "VARCHAR(64)",
        "needs_review": "BOOLEAN",
        "honeymind_result": "JSON",
    },
    "ip_info": {"lat": "FLOAT", "lon": "FLOAT"},
    "users": {
        "telegram_chat_id": "VARCHAR(64)",
        "telegram_username": "VARCHAR(64)",
        "telegram_link_code": "VARCHAR(32)",
        "telegram_link_expires": "TIMESTAMP",
    },
    "session_assessments": {
        "threat_score": "INTEGER",
        "download_then_execute": "BOOLEAN",
        "ssh_client": "VARCHAR(128)",
    },
}


def init_db(engine: Engine) -> None:
    Base.metadata.create_all(engine)  # TODO: Alembic-миграции, когда схема стабилизируется
    insp = inspect(engine)
    with engine.begin() as conn:
        for table, columns in LATE_COLUMNS.items():
            have = {c["name"] for c in insp.get_columns(table)}
            for name, sql_type in columns.items():
                if name not in have:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {sql_type}"))
    seed_roles(engine)


def seed_roles(engine: Engine) -> None:
    """Системные роли приводятся к описанию в коде при каждом старте (права обновляются вместе с версией)."""
    from .permissions import BUILTIN_ROLES
    with Session(engine) as db:
        for name, (title, desc, perms) in BUILTIN_ROLES.items():
            row = db.query(Role).filter(Role.name == name).one_or_none()
            if row is None:
                db.add(Role(name=name, title=title, description=desc, permissions=list(perms), is_system=True))
            else:
                row.title, row.description, row.permissions, row.is_system = title, desc, list(perms), True
        db.commit()


def get_db(request: Request) -> Iterator[Session]:
    factory: sessionmaker[Session] = request.app.state.session_factory
    with factory() as session:
        yield session
