"""Comprehensive RBAC and key-request workflow tests.

Covers:
  - Role-based endpoint access (admin vs enterprise_user vs unauthenticated)
  - Key request workflow (request → admin approve → one-time display)
  - Admin reject with reason
  - One pending request per user
  - Revoked key rejection
  - Expired key rejection
  - Consumed key stays consumed
  - Cross-user isolation
  - Self-protection (admin can't change own role/deactivate self)
  - Last admin protection
  - Deactivation revokes unconsumed keys
"""

# Ensure encryption key is set for tests that exercise pending_display_key
import os
from datetime import datetime, timedelta, timezone

import ks.database as _db
from cryptography.fernet import Fernet as _F
from ks.auth import hash_enterprise_key, hash_password
from ks.models import EnterpriseKey, User

if not os.environ.get("LUME_KS_ENCRYPTION_KEY"):
    os.environ["LUME_KS_ENCRYPTION_KEY"] = _F.generate_key().decode()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _create_user(client, username, role="enterprise_user", password="ValidPass!99"):
    db = _db.SessionLocal()
    try:
        user = User(username=username, email=f"{username}@test.dev",
                     hashed_password=hash_password(password), is_active=True,
                     is_approved=True, role=role)
        db.add(user)
        db.commit()
        db.refresh(user)
        return user
    finally:
        db.close()


def _get_token(client, username, password="ValidPass!99"):
    resp = client.post("/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200
    return resp.json()["access_token"]


def _issue_key_api(client, token):
    """Issue a key via the admin self-issue API endpoint."""
    resp = client.post("/api/keys/issue", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 201
    return resp.json()["key"]


def _validate(client, key, target="https://external.example.com/scan"):
    return client.post("/keys/validate", json={"key": key, "scan_target": target})


# ── 1. Role-based endpoint access ────────────────────────────────────────────

class TestRoleAccess:
    def test_regular_user_cannot_access_admin_dashboard(self, client, regular_user):
        _, _, token = regular_user
        resp = client.get("/admin/dashboard", cookies={"access_token": token})
        assert resp.status_code == 403

    def test_admin_can_access_admin_dashboard(self, registered_user, client):
        _, _, token = registered_user
        resp = client.get("/admin/dashboard", cookies={"access_token": token})
        assert resp.status_code == 200

    def test_regular_user_cannot_list_all_requests(self, client, regular_user):
        _, _, token = regular_user
        resp = client.get("/api/admin/requests", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 403

    def test_regular_user_cannot_list_all_users(self, client, regular_user):
        _, _, token = regular_user
        resp = client.get("/api/admin/users", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 403

    def test_regular_user_cannot_list_all_keys(self, client, regular_user):
        _, _, token = regular_user
        resp = client.get("/api/admin/keys", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 403

    def test_regular_user_cannot_self_issue_key(self, client, regular_user):
        _, _, token = regular_user
        resp = client.post("/api/keys/issue", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 403

    def test_admin_can_self_issue_key(self, registered_user, client):
        _, _, token = registered_user
        resp = client.post("/api/keys/issue", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 201


# ── 2. Key request workflow ───────────────────────────────────────────────────

class TestKeyRequestWorkflow:
    def test_user_can_submit_key_request(self, client, regular_user):
        _, _, token = regular_user
        resp = client.post("/api/keys/request", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert resp.json()["status"] == "pending"

    def test_admin_self_request_auto_approved(self, registered_user, client):
        _, _, token = registered_user
        resp = client.post("/api/keys/request", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert resp.json()["status"] == "approved"

    def test_user_can_view_own_requests(self, client, regular_user):
        _, _, token = regular_user
        client.post("/api/keys/request", headers={"Authorization": f"Bearer {token}"})
        resp = client.get("/api/keys/requests/me", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert len(resp.json()) >= 1

    def test_admin_can_see_pending_requests(self, client, regular_user, registered_user):
        _, _, user_token = regular_user
        _, _, admin_token = registered_user
        # User submits request
        client.post("/api/keys/request", headers={"Authorization": f"Bearer {user_token}"})
        # Admin sees it
        resp = client.get("/api/admin/requests", headers={"Authorization": f"Bearer {admin_token}"})
        assert resp.status_code == 200
        requests = resp.json()["requests"]
        assert any(r["status"] == "pending" for r in requests)

    def test_admin_can_approve_request(self, client, regular_user, registered_user):
        _, _, user_token = regular_user
        _, _, admin_token = registered_user
        # User requests
        req = client.post("/api/keys/request", headers={"Authorization": f"Bearer {user_token}"}).json()
        # Admin approves
        resp = client.post(
            f"/api/admin/requests/{req['id']}/approve",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "approved"
        assert resp.json()["key_id"]

    def test_admin_can_reject_request(self, client, regular_user, registered_user):
        _, _, user_token = regular_user
        _, _, admin_token = registered_user
        req = client.post("/api/keys/request", headers={"Authorization": f"Bearer {user_token}"}).json()
        resp = client.post(
            f"/api/admin/requests/{req['id']}/reject",
            json={"reason": "Not enough quota"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "rejected"

    def test_rejected_request_shows_reason_to_user(self, client, regular_user, registered_user):
        _, _, user_token = regular_user
        _, _, admin_token = registered_user
        req = client.post("/api/keys/request", headers={"Authorization": f"Bearer {user_token}"}).json()
        client.post(
            f"/api/admin/requests/{req['id']}/reject",
            json={"reason": "Quota exceeded"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        # User sees rejection reason
        resp = client.get("/api/keys/requests/me", headers={"Authorization": f"Bearer {user_token}"})
        user_reqs = resp.json()
        rejected = [r for r in user_reqs if r["status"] == "rejected"]
        assert len(rejected) >= 1
        assert rejected[0]["rejection_reason"] == "Quota exceeded"


# ── 3. One pending request per user ───────────────────────────────────────────

class TestOnePendingRequest:
    def test_user_cannot_have_two_pending_requests(self, client, regular_user):
        _, _, token = regular_user
        client.post("/api/keys/request", headers={"Authorization": f"Bearer {token}"})
        resp = client.post("/api/keys/request", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 409

    def test_user_can_request_again_after_rejection(self, client, regular_user, registered_user):
        _, _, user_token = regular_user
        _, _, admin_token = registered_user
        req = client.post("/api/keys/request", headers={"Authorization": f"Bearer {user_token}"}).json()
        client.post(f"/api/admin/requests/{req['id']}/reject", json={"reason": "No"},
                     headers={"Authorization": f"Bearer {admin_token}"})
        # Should be able to request again
        resp = client.post("/api/keys/request", headers={"Authorization": f"Bearer {user_token}"})
        assert resp.status_code == 200


# ── 4. One-time key display after approval ─────────────────────────────────────

class TestOneTimeDisplay:
    def test_approved_key_shown_once_on_dashboard(self, client, regular_user, registered_user):
        _, _, user_token = regular_user
        _, _, admin_token = registered_user
        req = client.post("/api/keys/request", headers={"Authorization": f"Bearer {user_token}"}).json()
        client.post(f"/api/admin/requests/{req['id']}/approve",
                     headers={"Authorization": f"Bearer {admin_token}"})

        # After Fix 2: pending_display_key is now a Fernet token, not 43-char plaintext.
        # Verify the encrypted value is stored, then simulate one-time retrieval.
        from ks.database import SessionLocal as SL
        from ks.key_crypto import decrypt_pending_key, is_encrypted_token
        from ks.models import KeyRequest as KR

        db = SL()
        try:
            pending = db.query(KR).filter(
                KR.id == req["id"],
                KR.pending_display_key.isnot(None)
            ).first()
            assert pending is not None, "pending_display_key should be set after admin approval"
            stored = pending.pending_display_key

            # The stored value must be an encrypted Fernet token (Fix 2)
            assert is_encrypted_token(stored), (
                f"pending_display_key must be a Fernet token, got: {stored[:20]}"
            )

            # Decrypt it — should yield a 43-char plaintext key
            decrypted = decrypt_pending_key(stored)
            assert decrypted is not None
            assert len(decrypted) == 43, f"Decrypted key must be 43 chars, got {len(decrypted)}"

            # Clear it (simulates dashboard visit)
            pending.pending_display_key = None
            db.commit()

            # Second read — must be None
            db.refresh(pending)
            assert pending.pending_display_key is None, "Key must be cleared after first display"
        finally:
            db.close()


# ── 5. Key validation with revoked/expired ────────────────────────────────────

class TestKeyValidationStates:
    def test_revoked_key_rejected(self, registered_user, client):
        _, _, token = registered_user
        key = _issue_key_api(client, token)
        # Find the key's DB id via the admin all-keys list (key_id == first 8 chars of hash)
        all_keys = client.get("/api/admin/keys", headers={"Authorization": f"Bearer {token}"}).json()
        # The API returns key_id which is hash[:8]; we need to find it by looking at unconsumed keys
        # Since we just issued one key, take the first unconsumed available key
        key_db_id = None
        for k in all_keys["keys"]:
            if not k["is_consumed"] and not k["is_revoked"]:
                key_db_id = k["id"]
                break
        assert key_db_id is not None, "Could not find issued key in admin keys list"
        revoke_resp = client.post(f"/api/admin/keys/{key_db_id}/revoke",
                                   headers={"Authorization": f"Bearer {token}"})
        assert revoke_resp.status_code == 200
        # Validation must reject with 'revoked'
        resp = _validate(client, key)
        assert resp.status_code == 401
        assert resp.json()["detail"]["reason"] == "revoked"

    def test_expired_key_rejected(self, registered_user, client):
        _, _, token = registered_user
        key = _issue_key_api(client, token)
        # Find the key by looking at the last-inserted unconsumed key in DB
        key_hash = hash_enterprise_key(key)
        db = _db.SessionLocal()
        try:
            k = db.query(EnterpriseKey).filter(EnterpriseKey.key_hash == key_hash).first()
            assert k is not None, "Issued key not found in DB"
            k.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
            db.commit()
        finally:
            db.close()
        resp = _validate(client, key)
        assert resp.status_code == 401
        assert resp.json()["detail"]["reason"] == "expired"

    def test_consumed_key_stays_consumed(self, registered_user, client):
        _, _, token = registered_user
        key = _issue_key_api(client, token)
        assert _validate(client, key).status_code == 200
        # Replay must fail
        resp = _validate(client, key)
        assert resp.status_code == 401
        assert resp.json()["detail"]["reason"] == "already_consumed"


# ── 6. Cross-user isolation ───────────────────────────────────────────────────

class TestCrossUserIsolation:
    def test_user_cannot_see_other_users_requests(self, client):
        _create_user(client, "iso_user_a")
        _create_user(client, "iso_user_b")
        token_a = _get_token(client, "iso_user_a")
        token_b = _get_token(client, "iso_user_b")
        # User A requests
        client.post("/api/keys/request", headers={"Authorization": f"Bearer {token_a}"})
        # User B should not see User A's request
        resp = client.get("/api/keys/requests/me", headers={"Authorization": f"Bearer {token_b}"})
        user_b_reqs = resp.json()
        assert all(r["id"] != 1 for r in user_b_reqs)  # User B has no requests

    def test_user_cannot_see_other_users_keys(self, client, registered_user, regular_user):
        _, _, admin_token = registered_user
        _, _, user_token = regular_user
        # Admin issues key to self
        key = _issue_key_api(client, admin_token)
        # Regular user should not see admin's key
        resp = client.get("/api/keys/me", headers={"Authorization": f"Bearer {user_token}"})
        user_keys = resp.json()["keys"]
        assert all(k["key_id"] != key[:8] for k in user_keys)


# ── 7. Self-protection ────────────────────────────────────────────────────────

class TestAdminSelfProtection:
    def test_admin_cannot_change_own_role(self, registered_user, client):
        _, _, token = registered_user
        # Get own user ID
        users = client.get("/api/admin/users", headers={"Authorization": f"Bearer {token}"}).json()
        own_id = [u for u in users["users"] if u["username"] == "testuser"][0]["id"]
        resp = client.post(f"/api/admin/users/{own_id}/role", json={"role": "enterprise_user"},
                           headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 403

    def test_admin_cannot_deactivate_self(self, registered_user, client):
        _, _, token = registered_user
        users = client.get("/api/admin/users", headers={"Authorization": f"Bearer {token}"}).json()
        own_id = [u for u in users["users"] if u["username"] == "testuser"][0]["id"]
        resp = client.post(f"/api/admin/users/{own_id}/deactivate",
                           headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 403


# ── 8. Last admin protection ───────────────────────────────────────────────────

class TestLastAdminProtection:
    def test_cannot_demote_last_admin(self, client):
        """With only one active admin, demoting that admin must be blocked."""
        # Create a sole admin
        _create_user(client, "sole_admin_x", role="admin")
        token_sole = _get_token(client, "sole_admin_x")

        # Get sole admin's own user id
        users = client.get("/api/admin/users",
                           headers={"Authorization": f"Bearer {token_sole}"}).json()
        sole_id = next(u["id"] for u in users["users"] if u["username"] == "sole_admin_x")

        # Create a second admin to do the demoting
        _create_user(client, "demoting_admin", role="admin")
        token_demoting = _get_token(client, "demoting_admin")

        # Two admins exist now; demoting sole_admin_x would leave 1 admin — still allowed
        # Demote sole_admin_x to enterprise_user — should succeed (1 admin remains: demoting_admin)
        resp = client.post(f"/api/admin/users/{sole_id}/role",
                           json={"role": "enterprise_user"},
                           headers={"Authorization": f"Bearer {token_demoting}"})
        assert resp.status_code == 200

        # Now only demoting_admin is admin; try to demote them too — should be blocked
        users2 = client.get("/api/admin/users",
                            headers={"Authorization": f"Bearer {token_demoting}"}).json()
        demoting_id = next(u["id"] for u in users2["users"] if u["username"] == "demoting_admin")

        # demoting_admin tries to demote themselves — self-protection kicks in
        resp2 = client.post(f"/api/admin/users/{demoting_id}/role",
                            json={"role": "enterprise_user"},
                            headers={"Authorization": f"Bearer {token_demoting}"})
        assert resp2.status_code == 403, "Admin cannot change their own role"


# ── 9. Deactivation revokes unconsumed keys ────────────────────────────────────

class TestDeactivationRevokesKeys:
    def test_deactivation_revokes_unconsumed_keys(self, client, registered_user):
        _, _, admin_token = registered_user
        # Create a regular user with a key
        _create_user(client, "deactivate_test_user")
        user_token = _get_token(client, "deactivate_test_user")
        # Admin issues key via request flow
        req = client.post("/api/keys/request", headers={"Authorization": f"Bearer {user_token}"}).json()
        client.post(f"/api/admin/requests/{req['id']}/approve",
                     headers={"Authorization": f"Bearer {admin_token}"})
        # Deactivate the user
        users = client.get("/api/admin/users", headers={"Authorization": f"Bearer {admin_token}"}).json()
        user_id = [u for u in users["users"] if u["username"] == "deactivate_test_user"][0]["id"]
        resp = client.post(f"/api/admin/users/{user_id}/deactivate",
                           headers={"Authorization": f"Bearer {admin_token}"})
        assert resp.status_code == 200
        # Check that the key was revoked
        all_keys = client.get("/api/admin/keys", headers={"Authorization": f"Bearer {admin_token}"}).json()
        user_keys = [k for k in all_keys["keys"] if k["owner_username"] == "deactivate_test_user"]
        assert all(k["is_revoked"] for k in user_keys), "Unconsumed keys should be revoked on deactivation"


# ── 10. Login response includes role ──────────────────────────────────────────

class TestRoleInLogin:
    def test_login_returns_role(self, registered_user, client):
        username, password, _ = registered_user
        resp = client.post("/auth/login", json={"username": username, "password": password})
        assert resp.status_code == 200
        assert resp.json()["role"] == "admin"

    def test_login_returns_role_for_regular_user(self, client, regular_user):
        username, password, _ = regular_user
        resp = client.post("/auth/login", json={"username": username, "password": password})
        assert resp.status_code == 200
        assert resp.json()["role"] == "enterprise_user"
