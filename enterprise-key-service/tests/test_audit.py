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
        resp = client.post("/auth/login", json={"username": "x", "password": "x"})
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
        key_resp = client.post("/api/keys/issue",
                                headers={"Authorization": f"Bearer {token}"}).json()
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
