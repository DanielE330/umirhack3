from __future__ import annotations

from collections.abc import Iterator

from fastapi import Request
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from .models import Base


def make_engine(url: str) -> Engine:
    if url.startswith("sqlite"):
        kwargs: dict = {"connect_args": {"check_same_thread": False}}
        if ":memory:" in url or url.endswith("://"):
            kwargs["poolclass"] = StaticPool
        return create_engine(url, **kwargs)
    return create_engine(url, pool_pre_ping=True)


# Колонки, добавленные после первого релиза: create_all не меняет существующие таблицы
LATE_COLUMNS = {"traps": {"machine_vmid": "INTEGER"}}


def init_db(engine: Engine) -> None:
    Base.metadata.create_all(engine)  # TODO: Alembic-миграции, когда схема стабилизируется
    insp = inspect(engine)
    with engine.begin() as conn:
        for table, columns in LATE_COLUMNS.items():
            have = {c["name"] for c in insp.get_columns(table)}
            for name, sql_type in columns.items():
                if name not in have:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {sql_type}"))


def get_db(request: Request) -> Iterator[Session]:
    factory: sessionmaker[Session] = request.app.state.session_factory
    with factory() as session:
        yield session
