"""Pytest fixtures and path setup.

All Aegis packages (server/ml/scanner/agent) are tested in a single dev venv.
aegis_crypto must be installed as editable.
"""
import os
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
for pkg_dir in ["server", "ml", "scanner", "agent"]:
    sys.path.insert(0, str(ROOT / pkg_dir))

# Run the server with an isolated temporary SQLite (BEFORE the app is imported).
_TMP_DB = Path(tempfile.gettempdir()) / "aegis_test.db"
os.environ["AEGIS_DATABASE_URL"] = f"sqlite:///{_TMP_DB.as_posix()}"


@pytest.fixture()
def client():
    """A FastAPI TestClient with a clean schema for each test."""
    import app.main as main
    from app.database import Base, engine
    from fastapi.testclient import TestClient

    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    return TestClient(main.app)
