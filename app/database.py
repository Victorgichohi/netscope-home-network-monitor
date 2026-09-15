from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import get_settings


class Base(DeclarativeBase):
    pass


settings = get_settings()
connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, connect_args=connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)


def get_db() -> Generator[Session, None, None]:
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def migrate_schema() -> None:
    """Apply the small additive migrations needed by the self-contained MVP."""
    inspector = inspect(engine)
    upgrades = {
        "devices": {
            "category": "VARCHAR(32) NOT NULL DEFAULT 'unknown'",
            "trust_status": "VARCHAR(32) NOT NULL DEFAULT 'unknown'",
        },
        "traffic_flows": {
            "direction": "VARCHAR(16) NOT NULL DEFAULT 'outbound'",
        },
    }
    with engine.begin() as connection:
        for table_name, columns in upgrades.items():
            if table_name not in inspector.get_table_names():
                continue
            existing = {column["name"] for column in inspector.get_columns(table_name)}
            for column_name, definition in columns.items():
                if column_name not in existing:
                    connection.execute(
                        text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {definition}")
                    )
