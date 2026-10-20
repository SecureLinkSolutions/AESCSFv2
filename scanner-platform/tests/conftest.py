import os
from pathlib import Path

import fakeredis
import pytest

API_DIR = Path(__file__).resolve().parents[1] / "api"


@pytest.fixture(scope="session", autouse=True)
def _env(tmp_path_factory):
    db_path = tmp_path_factory.mktemp("db") / "test.sqlite"
    os.environ.update(
        DATABASE_URL=f"sqlite:///{db_path}",
        VALKEY_URL="redis://unused:6379/0",
        SECRET_KEY="test-secret-key-that-is-long-enough-123",
        COOKIE_SECURE="false",
        AUTHORISATION_DIR=str(tmp_path_factory.mktemp("authorisations")),
    )
    from alembic import command
    from alembic.config import Config

    cfg = Config(str(API_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(API_DIR / "migrations"))
    command.upgrade(cfg, "head")


@pytest.fixture
def valkey():
    return fakeredis.FakeRedis(decode_responses=True)


@pytest.fixture
def db():
    from sqlalchemy import text

    from app.db import get_engine, get_sessionmaker

    with get_sessionmaker()() as session:
        yield session
    # Raw SQL: the ORM refuses to delete audit_log rows, by design.
    with get_engine().begin() as conn:
        for table in ("audit_log", "scope_items", "authorisations", "clients", "users"):
            conn.execute(text(f"DELETE FROM {table}"))  # noqa: S608


@pytest.fixture
def app(valkey):
    from app.main import create_app
    from app.valkey import get_valkey

    application = create_app()
    application.dependency_overrides[get_valkey] = lambda: valkey
    return application


@pytest.fixture
def client(app):
    from fastapi.testclient import TestClient

    with TestClient(app) as c:
        yield c


@pytest.fixture
def user(db):
    from app.models import User
    from app.passwords import hash_password

    u = User(username="alice", password_hash=hash_password("correct horse battery"))
    db.add(u)
    db.commit()
    return u


def login(client, username="alice", password="correct horse battery"):
    page = client.get("/app/login")
    token = page.cookies.get("slscan_login_csrf")
    return client.post(
        "/app/login",
        data={"username": username, "password": password, "csrf_token": token},
        follow_redirects=False,
    )
