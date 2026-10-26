"""Pytest fixtures for HoneyShield test suites."""
from __future__ import annotations

import gc
import sqlite3
import sys
import tempfile
from pathlib import Path
from typing import Generator

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import pytest
from flask import Flask
from flask.testing import FlaskClient

from app import create_app


@pytest.fixture
def temp_db() -> Generator[Path, None, None]:
    """Provide an isolated temporary SQLite database path with robust Windows cleanup."""
    temp_dir = tempfile.TemporaryDirectory(prefix="hs-pytest-")
    db_path = Path(temp_dir.name) / "test.sqlite3"
    try:
        yield db_path
    finally:
        gc.collect()
        try:
            temp_dir.cleanup()
        except (PermissionError, OSError):
            pass


@pytest.fixture
def app(temp_db: Path) -> Generator[Flask, None, None]:
    """Create a configured test application instance using the isolated database."""
    application = create_app({
        "TESTING": True,
        "DATABASE": str(temp_db),
        "SECRET_KEY": "pytest-isolated-test-secret-key-2026",
        "HIGH_RISK_THRESHOLD": 50,
        "RISK_WINDOW_SECONDS": 180,
    })
    yield application


@pytest.fixture
def client(app: Flask) -> FlaskClient:
    """Provide a Flask test client for HTTP requests."""
    return app.test_client()


@pytest.fixture
def db_conn(temp_db: Path) -> Generator[sqlite3.Connection, None, None]:
    """Provide a direct connection to the test database with Row factory."""
    conn = sqlite3.connect(str(temp_db))
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()
