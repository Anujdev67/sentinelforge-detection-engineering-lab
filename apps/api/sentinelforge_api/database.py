"""Database lifecycle and FastAPI session dependency."""

from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from apps.api.sentinelforge_api.config import get_settings
from apps.api.sentinelforge_api.db_models import Base


class Database:
    """Own an engine and typed session factory for one application instance."""

    def __init__(self, url: str) -> None:
        connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
        self.engine: Engine = create_engine(url, pool_pre_ping=True, connect_args=connect_args)
        self.session_factory = sessionmaker(
            bind=self.engine, expire_on_commit=False, class_=Session
        )

    def create_schema(self) -> None:
        Base.metadata.create_all(self.engine)

    def session(self) -> Generator[Session, None, None]:
        with self.session_factory() as database_session:
            yield database_session


database = Database(get_settings().database_url)


def get_session() -> Generator[Session, None, None]:
    yield from database.session()
