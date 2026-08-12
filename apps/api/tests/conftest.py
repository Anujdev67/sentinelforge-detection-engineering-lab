"""Isolated FastAPI integration fixtures."""

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from apps.api.sentinelforge_api.config import Settings
from apps.api.sentinelforge_api.main import create_app


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    database_path = (tmp_path / "sentinelforge-test.db").as_posix()
    settings = Settings(
        env="test",
        demo_mode=True,
        database_url=f"sqlite:///{database_path}",
        cors_origins="http://localhost:5173",
    )
    with TestClient(create_app(settings=settings)) as test_client:
        yield test_client
