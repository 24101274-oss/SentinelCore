from pathlib import Path

from sqlalchemy import Engine, create_engine, event, inspect, text
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
        # Compatibilidad con la base de la primera versión sin eliminar evidencia.
        additions = {
            "blocks": {"verified_at": "DATETIME", "restored_at": "DATETIME"},
            "incidents": {
                "ai_started_at": "DATETIME",
                "category": "VARCHAR(40) NOT NULL DEFAULT 'possible_brute_force'",
            },
        }
        with engine.begin() as connection:
            for table, columns in additions.items():
                existing = {column["name"] for column in inspect(connection).get_columns(table)}
                for column, data_type in columns.items():
                    if column not in existing:
                        connection.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {data_type}"))
            # El estado histórico contained no era prueba de un rechazo real.
            connection.execute(text(
                "UPDATE incidents SET status = 'pending_verification' "
                "WHERE status = 'contained' AND EXISTS ("
                "SELECT 1 FROM blocks WHERE blocks.incident_id = incidents.id "
                "AND blocks.status = 'active' AND blocks.verified_at IS NULL)"
            ))
            connection.execute(text(
                "UPDATE incidents SET status = 'restoration_pending' "
                "WHERE status = 'contained' AND NOT EXISTS ("
                "SELECT 1 FROM blocks WHERE blocks.incident_id = incidents.id AND blocks.status = 'active')"
            ))
    except Exception:
        engine.dispose()
        raise
    return engine
