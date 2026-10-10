"""init_db() только create_all + ALTER на уже существующих таблицах (LATE_COLUMNS) —
на базе, созданной до HoneyMind, лента событий не должна ломаться на старте."""
from sqlalchemy import inspect, text

from app.db import LATE_COLUMNS, init_db, make_engine

NEW_EVENT_COLUMNS = {"threat_score", "category", "needs_review", "honeymind_result"}

# Схема events "до HoneyMind" — без новых колонок (достаточно для inspect(), FK не нужен для теста).
OLD_EVENTS_TABLE = """
CREATE TABLE events (
    id INTEGER PRIMARY KEY,
    uid VARCHAR(64) UNIQUE,
    trap_id INTEGER,
    ts DATETIME,
    received_at DATETIME,
    type VARCHAR(24),
    src_ip VARCHAR(64),
    src_port INTEGER,
    dst_port INTEGER,
    proto VARCHAR(16),
    session_id VARCHAR(64),
    username VARCHAR(128),
    password VARCHAR(256),
    command TEXT,
    data JSON
)
"""


def test_late_columns_added_to_preexisting_events_table(tmp_path):
    db_path = tmp_path / "old.db"
    old_engine = make_engine(f"sqlite:///{db_path}")
    with old_engine.begin() as conn:
        conn.execute(text(OLD_EVENTS_TABLE))
    have_before = {c["name"] for c in inspect(old_engine).get_columns("events")}
    assert not (have_before & NEW_EVENT_COLUMNS)  # старая база и в самом деле без новых колонок
    old_engine.dispose()

    # Как при обычном старте приложения: новый код открывает ту же базу и вызывает init_db().
    engine = make_engine(f"sqlite:///{db_path}")
    init_db(engine)

    have_after = {c["name"] for c in inspect(engine).get_columns("events")}
    assert NEW_EVENT_COLUMNS <= have_after
    # Старые данные/колонки не потеряны.
    assert {"id", "uid", "trap_id", "session_id", "command"} <= have_after


def test_init_db_idempotent_on_already_migrated_schema(tmp_path):
    """Повторный старт приложения (колонки уже есть) не должен падать на ALTER TABLE."""
    db_path = tmp_path / "fresh.db"
    engine = make_engine(f"sqlite:///{db_path}")
    init_db(engine)
    init_db(engine)  # не должно бросить "duplicate column"
    have = {c["name"] for c in inspect(engine).get_columns("events")}
    assert NEW_EVENT_COLUMNS <= have


def test_late_columns_covers_every_new_event_field():
    """Если кто-то добавит новое nullable-поле в Event, но забудет LATE_COLUMNS — тест должен упасть."""
    assert NEW_EVENT_COLUMNS <= LATE_COLUMNS["events"].keys()
