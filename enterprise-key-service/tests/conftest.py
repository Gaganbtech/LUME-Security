"""Pytest fixtures for the LUME Enterprise Key Service test suite."""

import os

import pytest

# Set env vars BEFORE any ks module is imported
os.environ["LUME_KS_SECRET_KEY"] = "test-secret-key-do-not-use-in-production-ever"
os.environ["LUME_KS_AUDIT_SECRET"] = "test-audit-secret-different-from-session"
os.environ["LUME_KS_DB_URL"] = "sqlite:///:memory:"

# Generate a Fernet key for tests that exercise pending_display_key encryption
from cryptography.fernet import Fernet as _Fernet  # noqa: E402

os.environ.setdefault("LUME_KS_ENCRYPTION_KEY", _Fernet.generate_key().decode())

from contextlib import asynccontextmanager  # noqa: E402

import ks.database as _db  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from ks.config import settings  # noqa: E402


@asynccontextmanager
async def _noop_lifespan(app):
    yield


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    """Reset the rate limiter storage between tests so limits don't carry over."""
    try:
        from ks.rate_limit import limiter
        limiter.reset()
    except Exception:
        pass
    yield
    try:
        from ks.rate_limit import limiter
        limiter.reset()
    except Exception:
        pass


@pytest.fixture(scope="function")
def client():
    settings.load()
    _db.init_db(db_url="sqlite:///:memory:")

    from ks.main import create_app
    app = create_app()
    app.router.lifespan_context = _noop_lifespan

    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


@pytest.fixture
def registered_user(client):
    """Create an ADMIN test account (most tests need to issue keys)."""
    from ks.auth import hash_password
    from ks.models import User

    username = "testuser"
    password = "SuperSecret!Pass99"

    db = _db.SessionLocal()
    try:
        user = User(
            username=username,
            email="test@local.dev",
            hashed_password=hash_password(password),
            is_active=True,
            is_approved=True,   # test admin is pre-approved
            role="admin",
        )
        db.add(user)
        db.commit()
    finally:
        db.close()

    resp = client.post("/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200, f"Login failed: {resp.text}"
    token = resp.json()["access_token"]
    return username, password, token


@pytest.fixture
def regular_user(client):
    """Create an ENTERPRISE_USER test account for RBAC tests."""
    from ks.auth import hash_password
    from ks.models import User

    username = "regularuser"
    password = "RegularPass!99"

    db = _db.SessionLocal()
    try:
        user = User(
            username=username,
            email="regular@test.dev",
            hashed_password=hash_password(password),
            is_active=True,
            is_approved=True,   # test user is pre-approved for RBAC tests
            role="enterprise_user",
        )
        db.add(user)
        db.commit()
    finally:
        db.close()

    resp = client.post("/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200, f"Login failed: {resp.text}"
    token = resp.json()["access_token"]
    return username, password, token


@pytest.fixture
def second_admin(client):
    """Create a second admin for multi-admin tests."""
    from ks.auth import hash_password
    from ks.models import User

    username = "admin2"
    password = "AdminTwoPass!99"

    db = _db.SessionLocal()
    try:
        user = User(
            username=username,
            email="admin2@test.dev",
            hashed_password=hash_password(password),
            is_active=True,
            is_approved=True,
            role="admin",
        )
        db.add(user)
        db.commit()
    finally:
        db.close()

    resp = client.post("/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200
    token = resp.json()["access_token"]
    return username, password, token
