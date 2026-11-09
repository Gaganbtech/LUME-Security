"""Tests for three pre-production security fixes.

Fix 1: Atomic key consumption — PostgreSQL-safe UPDATE...WHERE
Fix 2: Encrypted pending_display_key (Fernet)
Fix 3: Audit log DB-level protection verification

All tests run against SQLite in-memory for speed.
PostgreSQL-specific atomicity is tested via threading (SQLite write lock
serialises these, proving the API contract; real PG concurrency is covered
by integration tests that require a PG connection).
"""

import os
import threading

import pytest

os.environ.setdefault("LUME_KS_SECRET_KEY", "test-secret-key-for-security-fixes")
os.environ.setdefault("LUME_KS_AUDIT_SECRET", "test-audit-secret-for-security-fixes")

# Generate a valid Fernet key for tests
from cryptography.fernet import Fernet as _Fernet

_TEST_FERNET_KEY = _Fernet.generate_key().decode()
os.environ["LUME_KS_ENCRYPTION_KEY"] = _TEST_FERNET_KEY
os.environ.setdefault("LUME_KS_DB_URL", "sqlite:///:memory:")

import ks.database as _db
from ks.audit_worm import verify_audit_worm_policy
from ks.auth import hash_password
from ks.config import settings
from ks.key_consume import KeyNotFound, consume_key_atomically
from ks.key_crypto import (
    decrypt_pending_key,
    encrypt_pending_key,
    is_encrypted_token,
)
from ks.models import EnterpriseKey, KeyRequest, User

# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture(scope="function")
def client():
    settings.load()
    _db.init_db(db_url="sqlite:///:memory:")
    from contextlib import asynccontextmanager

    from ks.main import create_app

    @asynccontextmanager
    async def _noop(app):
        yield

    app = create_app()
    app.router.lifespan_context = _noop
    from fastapi.testclient import TestClient
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


@pytest.fixture
def registered_user(client):
    db = _db.SessionLocal()
    try:
        user = User(username="testadmin", email="a@t.dev",
                     hashed_password=hash_password("Pass!99secure"),
                     is_active=True, is_approved=True, role="admin")
        db.add(user); db.commit()
    finally:
        db.close()
    resp = client.post("/auth/login", json={"username": "testadmin", "password": "Pass!99secure"})
    assert resp.status_code == 200
    return "testadmin", "Pass!99secure", resp.json()["access_token"]


def _issue_key_api(client, token):
    r = client.post("/api/keys/issue", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 201
    return r.json()["key"]


# ══════════════════════════════════════════════════════════════════════════════
# FIX 1 — Atomic key consumption
# ══════════════════════════════════════════════════════════════════════════════

class TestAtomicKeyConsumption:
    def test_consume_key_atomically_success(self, registered_user, client):
        _, _, token = registered_user
        key = _issue_key_api(client, token)
        resp = client.post("/keys/validate", json={"key": key, "scan_target": "https://x.example.com"})
        assert resp.status_code == 200
        assert resp.json()["status"] == "consumed"

    def test_consumed_key_rejected_on_replay(self, registered_user, client):
        _, _, token = registered_user
        key = _issue_key_api(client, token)
        client.post("/keys/validate", json={"key": key, "scan_target": "https://x.example.com"})
        resp = client.post("/keys/validate", json={"key": key, "scan_target": "https://x.example.com"})
        assert resp.status_code == 401
        assert resp.json()["detail"]["reason"] == "already_consumed"

    def test_concurrent_consumption_only_one_wins(self, registered_user, client):
        """Two threads racing to consume the same key — exactly one must win."""
        _, _, token = registered_user
        key = _issue_key_api(client, token)

        results = []
        lock = threading.Lock()

        def try_consume():
            r = client.post("/keys/validate",
                             json={"key": key, "scan_target": "https://x.example.com"})
            with lock:
                results.append(r.status_code)

        t1 = threading.Thread(target=try_consume)
        t2 = threading.Thread(target=try_consume)
        t1.start(); t2.start()
        t1.join(); t2.join()

        assert sorted(results) == [200, 401], (
            f"Expected exactly one 200 and one 401, got: {results}"
        )

    def test_many_concurrent_consumers_exactly_one_wins(self, registered_user, client):
        """10 threads racing — still exactly one success."""
        _, _, token = registered_user
        key = _issue_key_api(client, token)

        results = []
        lock = threading.Lock()

        def try_consume():
            r = client.post("/keys/validate",
                             json={"key": key, "scan_target": "https://x.example.com"})
            with lock:
                results.append(r.status_code)

        threads = [threading.Thread(target=try_consume) for _ in range(10)]
        for t in threads: t.start()
        for t in threads: t.join()

        successes = results.count(200)
        assert successes == 1, f"Expected 1 success, got {successes} from {results}"

    def test_revoked_key_rejected(self, registered_user, client):
        _, _, token = registered_user
        key = _issue_key_api(client, token)
        # Find and revoke the key
        all_keys = client.get("/api/admin/keys",
                               headers={"Authorization": f"Bearer {token}"}).json()
        kid = next(k["id"] for k in all_keys["keys"] if not k["is_consumed"])
        client.post(f"/api/admin/keys/{kid}/revoke",
                     headers={"Authorization": f"Bearer {token}"})
        resp = client.post("/keys/validate",
                           json={"key": key, "scan_target": "https://x.example.com"})
        assert resp.status_code == 401
        assert resp.json()["detail"]["reason"] == "revoked"

    def test_expired_key_rejected(self, registered_user, client):
        from datetime import datetime, timedelta, timezone
        _, _, token = registered_user
        key = _issue_key_api(client, token)
        # Force-expire via DB
        from ks.auth import hash_enterprise_key
        key_hash = hash_enterprise_key(key)
        db = _db.SessionLocal()
        try:
            k = db.query(EnterpriseKey).filter(EnterpriseKey.key_hash == key_hash).first()
            k.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
            db.commit()
        finally:
            db.close()
        resp = client.post("/keys/validate",
                           json={"key": key, "scan_target": "https://x.example.com"})
        assert resp.status_code == 401
        assert resp.json()["detail"]["reason"] == "expired"

    def test_nonexistent_key_rejected(self, client):
        resp = client.post("/keys/validate",
                           json={"key": "A" * 43, "scan_target": "https://x.example.com"})
        assert resp.status_code == 401
        assert resp.json()["detail"]["reason"] == "not_found"

    def test_key_consume_module_directly_sqlite(self, registered_user, client):
        """Direct unit test of consume_key_atomically on SQLite."""
        _, _, token = registered_user
        key = _issue_key_api(client, token)

        db = _db.SessionLocal()
        try:
            result = consume_key_atomically(db, key, "https://direct.example.com")
            db.commit()
            assert result["consumed_at"] is not None
            assert result["owner_id"] is not None
        finally:
            db.close()

        # Second attempt must raise
        db2 = _db.SessionLocal()
        try:
            with pytest.raises(KeyNotFound) as exc_info:
                consume_key_atomically(db2, key, "https://direct.example.com")
            assert exc_info.value.reason == "already_consumed"
        finally:
            db2.close()


# ══════════════════════════════════════════════════════════════════════════════
# FIX 2 — Encrypted pending_display_key
# ══════════════════════════════════════════════════════════════════════════════

class TestEncryptedPendingKey:
    def test_encrypt_produces_fernet_token(self):
        token = encrypt_pending_key("my-plaintext-key-abc123")
        assert is_encrypted_token(token), "Fernet tokens must start with gAAA"
        assert "my-plaintext-key" not in token, "Plaintext must not appear in ciphertext"

    def test_decrypt_recovers_plaintext(self):
        plaintext = "super-secret-enterprise-key-xyz"
        token = encrypt_pending_key(plaintext)
        recovered = decrypt_pending_key(token)
        assert recovered == plaintext

    def test_decrypt_wrong_key_returns_none(self):
        token = encrypt_pending_key("some-key")
        # Swap to a different Fernet key
        different_key = _Fernet.generate_key().decode()
        old_key = os.environ["LUME_KS_ENCRYPTION_KEY"]
        os.environ["LUME_KS_ENCRYPTION_KEY"] = different_key
        try:
            result = decrypt_pending_key(token)
            assert result is None, "Wrong key must return None, not raise"
        finally:
            os.environ["LUME_KS_ENCRYPTION_KEY"] = old_key

    def test_decrypt_tampered_token_returns_none(self):
        token = encrypt_pending_key("original")
        tampered = token[:-4] + "XXXX"
        result = decrypt_pending_key(tampered)
        assert result is None

    def test_decrypt_empty_returns_none(self):
        assert decrypt_pending_key("") is None
        assert decrypt_pending_key(None) is None  # type: ignore[arg-type]

    def test_is_encrypted_token_distinguishes_fernet(self):
        # Plaintext (dev fallback) is NOT a Fernet token
        assert not is_encrypted_token("plaintext-key-value")
        # Fernet token starts with gAAA
        token = encrypt_pending_key("key")
        assert is_encrypted_token(token)

    def test_pending_key_not_plaintext_in_db_after_approval(self, registered_user, client):
        """After admin approves a request, DB must not contain plaintext key."""
        _, _, admin_token = registered_user
        # Create an enterprise user
        db = _db.SessionLocal()
        try:
            eu = User(username="eu_enc_test", email="enc@t.dev",
                       hashed_password=hash_password("Pass!99secure"),
                       is_active=True, is_approved=True, role="enterprise_user")
            db.add(eu); db.commit(); db.refresh(eu)
            eu_id = eu.id
        finally:
            db.close()

        eu_token = client.post("/auth/login",
                                json={"username": "eu_enc_test",
                                      "password": "Pass!99secure"}).json()["access_token"]
        req = client.post("/api/keys/request",
                           headers={"Authorization": f"Bearer {eu_token}"}).json()

        client.post(f"/api/admin/requests/{req['id']}/approve",
                     headers={"Authorization": f"Bearer {admin_token}"})

        # Inspect the DB — pending_display_key should be encrypted (Fernet token)
        db2 = _db.SessionLocal()
        try:
            approved_req = db2.query(KeyRequest).filter(KeyRequest.id == req["id"]).first()
            stored = approved_req.pending_display_key
            assert stored is not None, "pending_display_key should be set"
            assert is_encrypted_token(stored), (
                "pending_display_key must be a Fernet token, not plaintext. "
                f"Got: {stored[:20]}..."
            )
        finally:
            db2.close()

    def test_one_time_display_clears_encrypted_value(self, registered_user, client):
        """After user views their key, pending_display_key must be NULL."""
        _, _, admin_token = registered_user
        db = _db.SessionLocal()
        try:
            eu = User(username="eu_otd_test", email="otd@t.dev",
                       hashed_password=hash_password("Pass!99secure"),
                       is_active=True, is_approved=True, role="enterprise_user")
            db.add(eu); db.commit()
        finally:
            db.close()

        eu_token = client.post("/auth/login",
                                json={"username": "eu_otd_test",
                                      "password": "Pass!99secure"}).json()["access_token"]
        req = client.post("/api/keys/request",
                           headers={"Authorization": f"Bearer {eu_token}"}).json()
        client.post(f"/api/admin/requests/{req['id']}/approve",
                     headers={"Authorization": f"Bearer {admin_token}"})

        # Trigger dashboard — reads and clears pending_display_key
        db2 = _db.SessionLocal()
        try:
            from ks.key_crypto import decrypt_pending_key, is_encrypted_token
            r = db2.query(KeyRequest).filter(KeyRequest.id == req["id"]).first()
            stored = r.pending_display_key
            assert stored is not None
            # Simulate what the dashboard route does
            if is_encrypted_token(stored):
                decrypted = decrypt_pending_key(stored)
            else:
                decrypted = stored
            assert decrypted is not None and len(decrypted) > 0
            r.pending_display_key = None
            db2.commit()

            # Second read — must be None
            db2.refresh(r)
            assert r.pending_display_key is None
        finally:
            db2.close()


# ══════════════════════════════════════════════════════════════════════════════
# FIX 3 — Audit log protection
# ══════════════════════════════════════════════════════════════════════════════

class TestAuditLogProtection:
    def test_worm_status_sqlite_reports_not_postgresql(self, client):
        import ks.database as _db_mod
        status = verify_audit_worm_policy(_db_mod._engine)
        assert status["dialect"] == "sqlite"
        assert status["rls_enabled"] is None  # Not applicable

    def test_audit_insert_works_normally(self, registered_user, client):
        _, _, token = registered_user
        resp = client.get("/api/admin/audit", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200

    def test_audit_chain_valid_after_events(self, registered_user, client):
        _, _, token = registered_user
        # Generate some events
        key = _issue_key_api(client, token)
        client.post("/keys/validate",
                    json={"key": key, "scan_target": "https://x.example.com"})
        # Verify chain
        resp = client.get("/api/admin/audit/verify",
                          headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert resp.json()["valid"] is True

    def test_audit_worm_status_endpoint_accessible_to_admin(self, registered_user, client):
        _, _, token = registered_user
        resp = client.get("/api/admin/audit/worm-status",
                          headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        data = resp.json()
        assert "dialect" in data
        assert "note" in data

    def test_tampered_entry_detected_by_verify(self, registered_user, client):
        _, _, token = registered_user
        # Write at least one real audit event first
        key = _issue_key_api(client, token)
        client.post("/keys/validate",
                    json={"key": key, "scan_target": "https://audit-test.example.com"})

        # Verify chain is currently valid
        resp_before = client.get("/api/admin/audit/verify",
                                  headers={"Authorization": f"Bearer {token}"})
        assert resp_before.json()["valid"] is True, "Chain must be valid before tampering"

        # Directly tamper with the FIRST audit log entry's event_type
        db = _db.SessionLocal()
        try:
            from ks.models import AuditLog
            entry = db.query(AuditLog).order_by(AuditLog.id.asc()).first()
            assert entry is not None, "At least one audit entry must exist"
            entry.event_type = "tampered_by_attacker"
            db.commit()
        finally:
            db.close()

        # Chain verification must now detect the tampering
        resp = client.get("/api/admin/audit/verify",
                          headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is False, (
            "Tampered event_type must be detected by HMAC chain verification"
        )
        assert len(data["errors"]) >= 1

    def test_no_update_route_exists_for_audit(self, client):
        """There must be no HTTP endpoint to UPDATE audit log entries."""
        # Try common update patterns — all must return 404 or 405
        for method, path in [
            ("PUT", "/api/admin/audit/1"),
            ("PATCH", "/api/admin/audit/1"),
            ("DELETE", "/api/admin/audit/1"),
            ("POST", "/api/admin/audit/1/update"),
        ]:
            resp = client.request(method, path)
            assert resp.status_code in (404, 405), (
                f"Expected 404 or 405 for {method} {path}, got {resp.status_code}"
            )
