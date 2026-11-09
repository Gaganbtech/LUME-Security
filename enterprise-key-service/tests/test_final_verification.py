"""Final verification tests covering every gap identified in the RBAC audit.

Covers:
  - Key issuance (authenticated and unauthenticated)
  - One-time validation (successful, rejection of reused key)
  - Consumed key stays consumed after simulated scan failure / cancellation
  - Expired JWTs are rejected on all protected endpoints
  - Inactive users cannot log in or use existing tokens
  - Unauthenticated access to every protected endpoint returns 401
  - Cross-user key isolation (User A cannot see User B's keys)
  - /api/keys/me and /api/keys/issue unauthenticated rejection
"""



import ks.database as _db
from ks.auth import create_access_token, hash_password
from ks.models import User

# ── Helpers ───────────────────────────────────────────────────────────────────

def _create_user(username: str, password: str = "ValidPass!99") -> User:
    """Insert a test user directly into the DB (admin role, pre-approved)."""
    db = _db.SessionLocal()
    try:
        user = User(
            username=username,
            email=f"{username}@test.local",
            hashed_password=hash_password(password),
            is_active=True,
            is_approved=True,
            role="admin",
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user
    finally:
        db.close()


def _get_token(client, username: str, password: str = "ValidPass!99") -> str:
    resp = client.post("/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200, f"Login failed for {username}: {resp.text}"
    return resp.json()["access_token"]


def _issue_key(client, token: str) -> str:
    resp = client.post("/api/keys/issue", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 201
    return resp.json()["key"]


def _validate(client, key: str, target: str = "https://external.example.com/scan") -> int:
    resp = client.post("/keys/validate", json={"key": key, "scan_target": target})
    return resp.status_code


# ── 1. Key issuance ───────────────────────────────────────────────────────────

class TestKeyIssuance:
    def test_authenticated_user_can_issue_key(self, registered_user, client):
        _, _, token = registered_user
        resp = client.post("/api/keys/issue", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 201
        data = resp.json()
        assert len(data["key"]) == 43
        assert len(data["key_id"]) == 8

    def test_unauthenticated_cannot_issue_key(self, client):
        assert client.post("/api/keys/issue").status_code == 401

    def test_wrong_token_cannot_issue_key(self, client):
        resp = client.post(
            "/api/keys/issue",
            headers={"Authorization": "Bearer not.a.valid.jwt"},
        )
        assert resp.status_code == 401


# ── 2. One-time validation ────────────────────────────────────────────────────

class TestOneTimeValidation:
    def test_valid_key_consumed_on_first_use(self, registered_user, client):
        _, _, token = registered_user
        key = _issue_key(client, token)
        assert _validate(client, key) == 200

    def test_reused_key_rejected_with_already_consumed(self, registered_user, client):
        _, _, token = registered_user
        key = _issue_key(client, token)
        _validate(client, key)  # first use

        resp = client.post("/keys/validate", json={"key": key, "scan_target": "https://x.example.com"})
        assert resp.status_code == 401
        assert resp.json()["detail"]["reason"] == "already_consumed"

    def test_consumed_key_response_does_not_echo_key(self, registered_user, client):
        _, _, token = registered_user
        key = _issue_key(client, token)
        _validate(client, key)
        resp = client.post("/keys/validate", json={"key": key, "scan_target": "https://x.example.com"})
        assert key not in resp.text

    def test_nonexistent_key_rejected_with_not_found(self, client):
        resp = client.post(
            "/keys/validate",
            json={"key": "A" * 43, "scan_target": "https://x.example.com"},
        )
        assert resp.status_code == 401
        assert resp.json()["detail"]["reason"] == "not_found"


# ── 3. Consumed key stays consumed after scan failure / cancellation ──────────

class TestConsumedKeyPersistence:
    def test_consumed_key_stays_consumed_after_simulated_scan_failure(self, registered_user, client):
        """Consuming the key succeeds.  A subsequent 'retry' (scan re-run) must NOT re-consume.

        We simulate a scan failure by simply not using the scan result and then
        trying to re-validate the same key — which represents the scenario where
        a user re-runs the CLI after a failed scan.
        """
        _, _, token = registered_user
        key = _issue_key(client, token)

        # Step 1: key is consumed (scan starts)
        assert _validate(client, key) == 200

        # Step 2: scan "fails" — user tries the same key again
        retry = client.post(
            "/keys/validate",
            json={"key": key, "scan_target": "https://external.example.com/scan"},
        )
        assert retry.status_code == 401, "Consumed key must not be reusable after scan failure"
        assert retry.json()["detail"]["reason"] == "already_consumed"

    def test_consumed_key_stays_consumed_after_simulated_cancellation(self, registered_user, client):
        """Cancellation scenario: key consumed, then user cancels the scan mid-way.
        The key must remain consumed — no 'refund' path exists.
        """
        _, _, token = registered_user
        key = _issue_key(client, token)
        _validate(client, key)  # consumed

        # There is no 'unconsume' endpoint.  Trying to re-consume must fail.
        resp = client.post(
            "/keys/validate",
            json={"key": key, "scan_target": "https://cancel-target.example.com"},
        )
        assert resp.status_code == 401
        assert resp.json()["detail"]["reason"] == "already_consumed"

    def test_consumed_status_persists_in_listing(self, registered_user, client):
        _, _, token = registered_user
        key = _issue_key(client, token)
        _validate(client, key)

        listing = client.get(
            "/api/keys/me",
            headers={"Authorization": f"Bearer {token}"},
        ).json()
        assert listing["keys"][0]["is_consumed"] is True
        assert listing["keys"][0]["consumed_at"] is not None


# ── 4. Expired JWTs ───────────────────────────────────────────────────────────

class TestExpiredJWT:
    def _expired_token(self, username: str) -> str:
        """Create a JWT that expired one second ago."""
        return create_access_token(subject=username, expires_seconds=-1)

    def test_expired_token_rejected_on_api_issue(self, registered_user, client):
        username, _, _ = registered_user
        token = self._expired_token(username)
        resp = client.post("/api/keys/issue", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 401

    def test_expired_token_rejected_on_api_keys_me(self, registered_user, client):
        username, _, _ = registered_user
        token = self._expired_token(username)
        resp = client.get("/api/keys/me", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 401

    def test_expired_cookie_rejected_on_dashboard(self, registered_user, client):
        username, _, _ = registered_user
        expired_token = self._expired_token(username)
        # Inject the expired token as a cookie
        resp = client.get("/dashboard", cookies={"access_token": expired_token})
        assert resp.status_code == 401

    def test_expired_cookie_rejected_on_request_form(self, registered_user, client):
        username, _, _ = registered_user
        expired_token = self._expired_token(username)
        resp = client.post("/keys/request", cookies={"access_token": expired_token})
        assert resp.status_code == 401


# ── 5. Inactive users ─────────────────────────────────────────────────────────

class TestInactiveUsers:
    def test_inactive_user_cannot_login(self, client):
        user = _create_user("inactive_login_user")
        # Deactivate them
        db = _db.SessionLocal()
        try:
            db.query(User).filter(User.id == user.id).update({"is_active": False})
            db.commit()
        finally:
            db.close()
        resp = client.post(
            "/auth/login",
            json={"username": "inactive_login_user", "password": "ValidPass!99"},
        )
        assert resp.status_code == 401

    def test_inactive_user_token_rejected_on_api_endpoints(self, client):
        """A token issued before deactivation must be rejected after deactivation."""
        user = _create_user("inactive_token_user")
        # Issue a valid token while the user is still active
        token = create_access_token(subject=user.username, expires_seconds=3600)

        # Deactivate the user
        db = _db.SessionLocal()
        try:
            db.query(User).filter(User.id == user.id).update({"is_active": False})
            db.commit()
        finally:
            db.close()

        # Token must now be rejected (get_current_user checks is_active)
        resp = client.post("/api/keys/issue", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 401, "Inactive user's token must be rejected"

    def test_inactive_user_cookie_rejected_on_dashboard(self, client):
        user = _create_user("inactive_dashboard_user")
        token = create_access_token(subject=user.username, expires_seconds=3600)

        db = _db.SessionLocal()
        try:
            db.query(User).filter(User.id == user.id).update({"is_active": False})
            db.commit()
        finally:
            db.close()

        resp = client.get("/dashboard", cookies={"access_token": token})
        assert resp.status_code == 401


# ── 6. Unauthenticated access to all protected endpoints ─────────────────────

class TestUnauthenticatedAccess:
    def test_dashboard_requires_auth(self, client):
        assert client.get("/dashboard").status_code == 401

    def test_api_keys_issue_requires_auth(self, client):
        assert client.post("/api/keys/issue").status_code == 401

    def test_api_keys_me_requires_auth(self, client):
        assert client.get("/api/keys/me").status_code == 401

    def test_form_keys_request_requires_auth(self, client):
        assert client.post("/keys/request").status_code == 401

    def test_validate_is_public_by_design(self, client):
        """POST /keys/validate is intentionally unauthenticated — the key is the credential."""
        resp = client.post(
            "/keys/validate",
            json={"key": "A" * 43, "scan_target": "https://example.com"},
        )
        # 401 because key not found — NOT because unauthenticated
        assert resp.status_code == 401
        assert resp.json()["detail"]["reason"] == "not_found"


# ── 7. Cross-user key isolation ───────────────────────────────────────────────

class TestCrossUserIsolation:
    def test_user_a_cannot_see_user_b_keys(self, client):
        """User A's key listing must not include keys issued to User B."""
        _create_user("isolation_user_a")
        _create_user("isolation_user_b")

        token_a = _get_token(client, "isolation_user_a")
        token_b = _get_token(client, "isolation_user_b")

        # Issue one key for each user
        _issue_key(client, token_a)
        key_b = _issue_key(client, token_b)

        # User A's listing must NOT contain User B's key
        list_a = client.get(
            "/api/keys/me",
            headers={"Authorization": f"Bearer {token_a}"},
        ).json()
        assert all(k["key_id"] != key_b[:8] for k in list_a["keys"]), (
            "User A's key listing contains a key belonging to User B"
        )

    def test_user_b_cannot_see_user_a_keys(self, client):
        """Symmetric check."""
        _create_user("isolation_user_a2")
        _create_user("isolation_user_b2")

        token_a = _get_token(client, "isolation_user_a2")
        token_b = _get_token(client, "isolation_user_b2")

        key_a = _issue_key(client, token_a)
        _issue_key(client, token_b)

        list_b = client.get(
            "/api/keys/me",
            headers={"Authorization": f"Bearer {token_b}"},
        ).json()
        assert all(k["key_id"] != key_a[:8] for k in list_b["keys"])

    def test_user_a_token_issues_key_owned_by_a_not_b(self, client):
        """Keys issued with User A's token must be owned by User A."""
        _create_user("owner_check_user_a")
        _create_user("owner_check_user_b")

        token_a = _get_token(client, "owner_check_user_a")
        _issue_key(client, token_a)

        # User B sees zero keys
        list_b = client.get(
            "/api/keys/me",
            headers={"Authorization": f"Bearer {_get_token(client, 'owner_check_user_b')}"},
        ).json()
        assert len(list_b["keys"]) == 0, "User B must not see User A's keys"

    def test_validate_does_not_expose_owner_identity(self, client):
        """POST /keys/validate success must not reveal the owner's username."""
        _create_user("validate_owner_check")
        token = _get_token(client, "validate_owner_check")
        key = _issue_key(client, token)

        resp = client.post(
            "/keys/validate",
            json={"key": key, "scan_target": "https://external.example.com"},
        )
        assert resp.status_code == 200
        assert "validate_owner_check" not in resp.text
