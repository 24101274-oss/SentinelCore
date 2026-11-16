from pathlib import Path

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.engine import make_url
from sqlalchemy.pool import StaticPool

from backend.models import Base


def open_database(database_url: str) -> Engine:
    url = make_url(database_url)
    if url.get_backend_name() != "sqlite":
        raise ValueError("DATABASE_URL debe apuntar a una base SQLite")

    in_memory = not url.database or url.database == ":memory:"
    if not in_memory:
        Path(url.database).parent.mkdir(parents=True, exist_ok=True)

    options = {"poolclass": StaticPool} if in_memory else {}
    engine = create_engine(url, connect_args={"check_same_thread": False}, **options)

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(connection, _record) -> None:
        connection.execute("PRAGMA foreign_keys = ON")

    try:
        Base.metadata.create_all(engine)
    except Exception:
        engine.dispose()
        raise
    return engine
