"""Pytest fixtures ve yol ayarları.

Tüm Aegis paketleri (server/ml/scanner/agent) tek dev venv'inde test edilir.
aegis_crypto editable kurulu olmalı.
"""
import os
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
for pkg_dir in ["server", "ml", "scanner", "agent"]:
    sys.path.insert(0, str(ROOT / pkg_dir))

# Server'ı izole bir geçici SQLite ile çalıştır (app import edilmeden ÖNCE).
_TMP_DB = Path(tempfile.gettempdir()) / "aegis_test.db"
os.environ["AEGIS_DATABASE_URL"] = f"sqlite:///{_TMP_DB.as_posix()}"


@pytest.fixture()
def client():
    """Her test için temiz şemalı FastAPI TestClient."""
    import app.main as main
    from app.database import Base, engine
    from fastapi.testclient import TestClient

    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    return TestClient(main.app)
