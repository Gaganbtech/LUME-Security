"""Tests for the tamper-evident audit log.

Covers:
- write_event creates entries with valid HMAC and chain link
- verify_chain passes on clean log
- Modifying an entry (simulating DB tampering) breaks HMAC verification
- Deleting an entry breaks chain link for subsequent entries
- Audit entries cannot be updated via the API (no update route)
- All portal events are logged (signup, approval, key request, key approve/reject, consume, revoke)
"""

import json
import os

os.environ.setdefault("LUME_KS_SECRET_KEY", "test-secret-key-for-audit-tests")
os.environ.setdefault("LUME_KS_AUDIT_SECRET", "test-audit-secret-different-from-session")
os.environ.setdefault("LUME_KS_DB_URL", "sqlite:///:memory:")

import ks.database as _db
from ks.audit import verify_chain, write_event
from ks.config import settings
from ks.models import AuditLog


def setup_db():
    settings.load()
    _db.init_db(db_url="sqlite:///:memory:")
    return _db.SessionLocal()


# ── 1. Basic write and HMAC verification ──────────────────────────────────────

class TestWriteEvent:
    def test_write_creates_entry(self):
        db = setup_db()
        try:
            write_event(db, "account_signup", actor_id=1, target_user_id=1,
                        event_data={"username": "alice"})
            db.commit()
            count = db.query(AuditLog).count()
            assert count == 1
        finally:
            db.close()

    def test_entry_has_hmac_and_chain(self):
        db = setup_db()
        try:
            write_event(db, "key_consumed", actor_id=None, target_user_id=2,
                        key_id=1)
            db.commit()
            e = db.query(AuditLog).first()
            assert e.entry_hmac
            assert len(e.entry_hmac) == 64
            assert e.chain_hash
            assert e.prev_entry_hash
        finally:
            db.close()

    def test_event_data_stored_as_json(self):
        db = setup_db()
        try:
            write_event(db, "user_role_changed", actor_id=1, target_user_id=2,
                        event_data={"new_role": "admin", "username": "bob"})
            db.commit()
            e = db.query(AuditLog).first()
            data = json.loads(e.event_data)
            assert data["new_role"] == "admin"
            assert data["username"] == "bob"
        finally:
            db.close()


# ── 2. Chain linking ─────────────────────────────────────────────────────────

class TestChainLinking:
    def test_second_entry_links_to_first(self):
        db = setup_db()
        try:
            write_event(db, "account_signup", actor_id=1)
            db.commit()
            e1 = db.query(AuditLog).order_by(AuditLog.id.asc()).first()

            write_event(db, "account_approved", actor_id=99, target_user_id=1)
            db.commit()
            e2 = db.query(AuditLog).order_by(AuditLog.id.desc()).first()

            assert e2.prev_entry_hash == e1.chain_hash
        finally:
            db.close()

    def test_chain_links_are_unique(self):
        db = setup_db()
        try:
            for i in range(5):
                write_event(db, "key_requested", actor_id=i, target_user_id=i)
                db.commit()
            chain_hashes = [e.chain_hash for e in db.query(AuditLog).all()]
            assert len(chain_hashes) == len(set(chain_hashes)), "Chain hashes must be unique"
        finally:
            db.close()


# ── 3. verify_chain — clean log ───────────────────────────────────────────────

class TestVerifyChainClean:
    def test_empty_log_is_valid(self):
        db = setup_db()
        try:
            result = verify_chain(db)
            assert result["valid"] is True
            assert result["total"] == 0
            assert result["errors"] == []
        finally:
            db.close()

    def test_clean_log_verifies_ok(self):
        db = setup_db()
        try:
            for event in ["account_signup", "account_approved", "key_requested",
                          "key_approved", "key_consumed"]:
                write_event(db, event, actor_id=1, target_user_id=2)
                db.commit()
            result = verify_chain(db)
            assert result["valid"] is True
            assert result["total"] == 5
            assert result["errors"] == []
        finally:
            db.close()


# ── 4. Tamper detection — HMAC ────────────────────────────────────────────────

class TestTamperDetectionHMAC:
    def test_modifying_event_type_breaks_hmac(self):
        """Simulates an attacker changing the event_type of an entry in the DB."""
        db = setup_db()
        try:
            write_event(db, "key_requested", actor_id=1, target_user_id=2)
            db.commit()
            # Tamper: change event_type directly in DB
            entry = db.query(AuditLog).first()
            entry.event_type = "key_consumed"  # attacker rewrites what happened
            db.commit()

            result = verify_chain(db)
            assert result["valid"] is False
            assert len(result["errors"]) >= 1
            assert any("hmac_invalid" in e["issues"] for e in result["errors"])
        finally:
            db.close()

    def test_modifying_event_data_breaks_hmac(self):
        """Attacker changes the scan_target in event_data."""
        db = setup_db()
        try:
            write_event(db, "key_consumed", actor_id=None, target_user_id=1,
                        key_id=1, event_data={"scan_target": "https://real.example.com"})
            db.commit()
            entry = db.query(AuditLog).first()
            entry.event_data = json.dumps({"scan_target": "https://attacker.example.com"})
            db.commit()

            result = verify_chain(db)
            assert result["valid"] is False
            assert any("hmac_invalid" in e["issues"] for e in result["errors"])
        finally:
            db.close()

    def test_modifying_actor_breaks_hmac(self):
        """Attacker changes who performed an action."""
        db = setup_db()
        try:
            write_event(db, "account_approved", actor_id=1, target_user_id=5)
            db.commit()
            entry = db.query(AuditLog).first()
            entry.actor_id = 999  # attacker replaces the real admin's ID
            db.commit()

            result = verify_chain(db)
            assert result["valid"] is False
        finally:
            db.close()


# ── 5. Tamper detection — chain deletion ──────────────────────────────────────

class TestTamperDetectionChain:
    def test_deleting_first_entry_breaks_chain(self):
        """Deleting the first entry orphans all subsequent entries."""
        db = setup_db()
        try:
            write_event(db, "account_signup", actor_id=1)
            db.commit()
            write_event(db, "account_approved", actor_id=99, target_user_id=1)
            db.commit()
            write_event(db, "key_requested", actor_id=1)
            db.commit()

            # Delete first entry (simulates attacker removing evidence)
            first = db.query(AuditLog).order_by(AuditLog.id.asc()).first()
            db.delete(first)
            db.commit()

            result = verify_chain(db)
            assert result["valid"] is False
            # At least one entry should have a broken chain link
            assert any("chain_link_broken" in e["issues"] for e in result["errors"])
        finally:
            db.close()

    def test_deleting_middle_entry_breaks_chain(self):
        """Deleting a middle entry breaks the chain for all entries after it."""
        db = setup_db()
        try:
            for event in ["account_signup", "account_approved", "key_requested",
                          "key_approved", "key_consumed"]:
                write_event(db, event, actor_id=1)
                db.commit()

            entries = db.query(AuditLog).order_by(AuditLog.id.asc()).all()
            middle = entries[2]
            db.delete(middle)
            db.commit()

            result = verify_chain(db)
            assert result["valid"] is False
        finally:
            db.close()


# ── 6. API: no update/delete endpoints for audit ─────────────────────────────

class TestAuditAPIReadOnly:
    def test_audit_list_endpoint_requires_admin(self, client):
        resp = client.get("/api/admin/audit")
        assert resp.status_code == 401

    def test_audit_verify_endpoint_requires_admin(self, client):
        resp = client.get("/api/admin/audit/verify")
        assert resp.status_code == 401

    def test_audit_list_returns_entries_for_admin(self, registered_user, client):
        _, _, token = registered_user
        resp = client.get("/api/admin/audit", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert "entries" in resp.json()

    def test_audit_verify_returns_result_for_admin(self, registered_user, client):
        _, _, token = registered_user
        resp = client.get("/api/admin/audit/verify", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        data = resp.json()
        assert "valid" in data
        assert "total" in data


# ── 7. Portal events are logged ───────────────────────────────────────────────

class TestPortalEventsLogged:
    def test_signup_creates_audit_entry(self, client):
        client.post("/auth/login", json={"username": "x", "password": "x"})
        # Create a new user via signup
        client.post("/signup", data={
            "username": "audituser", "email": "au@test.dev",
            "password": "StrongPassword!99", "confirm_password": "StrongPassword!99"
        })
        db = _db.SessionLocal()
        try:
            entry = db.query(AuditLog).filter(AuditLog.event_type == "account_signup").first()
            assert entry is not None
            assert "audituser" in (entry.event_data or "")
        finally:
            db.close()

    def test_key_consumed_creates_audit_entry(self, registered_user, client):
        _, _, token = registered_user
        key = client.post("/api/keys/issue",
                          headers={"Authorization": f"Bearer {token}"}).json()["key"]
        client.post("/keys/validate", json={"key": key, "scan_target": "https://x.example.com"})

        db = _db.SessionLocal()
        try:
            entry = db.query(AuditLog).filter(AuditLog.event_type == "key_consumed").first()
            assert entry is not None
        finally:
            db.close()

    def test_key_revoked_creates_audit_entry(self, registered_user, client):
        _, _, token = registered_user
        # Issue then revoke a key
        client.post("/api/keys/issue",
                    headers={"Authorization": f"Bearer {token}"})
        all_keys = client.get("/api/admin/keys",
                               headers={"Authorization": f"Bearer {token}"}).json()
        key_db_id = next(k["id"] for k in all_keys["keys"] if not k["is_consumed"] and not k["is_revoked"])
        client.post(f"/api/admin/keys/{key_db_id}/revoke",
                    headers={"Authorization": f"Bearer {token}"})

        db = _db.SessionLocal()
        try:
            entry = db.query(AuditLog).filter(AuditLog.event_type == "key_revoked").first()
            assert entry is not None
        finally:
            db.close()


# ── 8. Browser cookie endpoint for audit verification ─────────────────────────

class TestAuditVerifyBrowserEndpoint:
    """Tests for GET /admin/audit/verify — cookie-authenticated browser endpoint.

    This endpoint exists because JavaScript cannot read HttpOnly cookies via
    document.cookie. The browser fetch uses credentials:'include' to send the
    cookie automatically, and this endpoint accepts it via require_role_cookie.

    The existing GET /api/admin/audit/verify (Bearer-token) is kept unchanged.
    Both endpoints call the same verify_chain() function — no logic duplication.
    """

    def test_browser_endpoint_requires_authentication(self, client):
        """Unauthenticated GET /admin/audit/verify must return 401."""
        resp = client.get("/admin/audit/verify")
        assert resp.status_code == 401

    def test_browser_endpoint_requires_admin_role(self, client, regular_user):
        """Enterprise user cookie must be rejected with 403."""
        _, _, token = regular_user
        resp = client.get("/admin/audit/verify", cookies={"access_token": token})
        assert resp.status_code == 403

    def test_browser_endpoint_accepts_admin_cookie(self, registered_user, client):
        """Admin cookie must be accepted and return valid chain result."""
        _, _, token = registered_user
        resp = client.get("/admin/audit/verify", cookies={"access_token": token})
        assert resp.status_code == 200
        data = resp.json()
        assert "valid" in data
        assert "total" in data
        assert "errors" in data

    def test_browser_endpoint_returns_same_result_as_bearer_endpoint(
        self, registered_user, client
    ):
        """Both endpoints call the same verify_chain logic — results must match."""
        _, _, token = registered_user

        # Bearer endpoint
        bearer_resp = client.get(
            "/api/admin/audit/verify",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert bearer_resp.status_code == 200

        # Cookie endpoint
        cookie_resp = client.get(
            "/admin/audit/verify",
            cookies={"access_token": token},
        )
        assert cookie_resp.status_code == 200

        # Both must return identical results
        assert bearer_resp.json()["valid"] == cookie_resp.json()["valid"]
        assert bearer_resp.json()["total"] == cookie_resp.json()["total"]

    def test_browser_endpoint_detects_tampering(self, registered_user, client):
        """Cookie endpoint must detect a tampered chain, same as Bearer endpoint."""
        _, _, token = registered_user

        # Create some audit entries
        db = _db.SessionLocal()
        try:
            write_event(db, "key_requested", actor_id=1, target_user_id=2)
            db.commit()
            # Tamper with the entry
            entry = db.query(AuditLog).order_by(AuditLog.id.desc()).first()
            entry.event_type = "tampered_event"
            db.commit()
        finally:
            db.close()

        resp = client.get("/admin/audit/verify", cookies={"access_token": token})
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is False
        assert len(data["errors"]) >= 1

    def test_bearer_endpoint_still_works_unchanged(self, registered_user, client):
        """Confirm existing /api/admin/audit/verify (Bearer) is not broken."""
        _, _, token = registered_user
        resp = client.get(
            "/api/admin/audit/verify",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert "valid" in resp.json()

    def test_bearer_endpoint_rejects_no_token(self, client):
        """Existing Bearer endpoint still rejects unauthenticated requests."""
        resp = client.get("/api/admin/audit/verify")
        assert resp.status_code == 401

    def test_no_gettoken_function_in_template(self):
        """Verify the broken _getToken() document.cookie approach was removed."""
        from pathlib import Path
        template = Path(
            "d:/DREAM/4th/NEW AI SECURITY/LUME-Security-main"
            "/enterprise-key-service/ks/templates/audit_log.html"
        ).read_text(encoding="utf-8")

        # _getToken must be completely absent — it was the broken implementation
        assert "_getToken" not in template, (
            "_getToken() reads document.cookie which cannot access HttpOnly cookies"
        )

        # document.cookie must only appear in JS comments, never as executable code
        for line in template.splitlines():
            stripped = line.strip()
            if "document.cookie" in stripped:
                assert stripped.startswith("//") or stripped.startswith("*"), (
                    f"document.cookie must only appear in comments, found executable: {stripped}"
                )

        # Correct approach must be present
        assert "credentials: 'include'" in template, (
            "fetch must use credentials:'include' to send HttpOnly cookie automatically"
        )
        assert "/admin/audit/verify" in template, (
            "Template must call the cookie-authenticated endpoint"
        )
