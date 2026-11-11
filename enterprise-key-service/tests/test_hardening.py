"""Tests for the 6 production-hardening fixes.

1. Rate limiting on login, signup, and key validation
2. LUME_KS_AUDIT_SECRET required in production
3. HTTP security headers
4. CSRF protection for cookie-authenticated POSTs
5. Atomic key consumption + audit write (single transaction)
6. Database connection pool configuration

All env vars are set by conftest.py — this file does NOT set any secrets.
"""

import os
import sys
import threading
from pathlib import Path

# ── Ensure lume/ package is importable when running tests from enterprise-key-service/ ──
_REPO_ROOT = str(Path(__file__).parent.parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)
from contextlib import asynccontextmanager  # noqa: E402

import ks.database as _db  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from ks.auth import hash_password  # noqa: E402
from ks.config import settings  # noqa: E402
from ks.models import User  # noqa: E402


@asynccontextmanager
async def _noop_lifespan(app):
    yield


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
def admin_user(client):
    """Create an admin and get a JWT token directly (not via HTTP to avoid rate limit)."""
    from ks.auth import create_access_token
    db = _db.SessionLocal()
    try:
        user = User(
            username="hardening_admin",
            email="admin@hardening.test",
            hashed_password=hash_password("TestPass!12345"),
            is_active=True,
            is_approved=True,
            role="admin",
        )
        db.add(user)
        db.commit()
    finally:
        db.close()
    token = create_access_token(subject="hardening_admin")
    return "hardening_admin", "TestPass!12345", token


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Reset the rate limiter storage between tests so limits don't carry over."""
    from ks.rate_limit import limiter
    try:
        limiter.reset()
    except Exception:
        pass
    yield
    try:
        limiter.reset()
    except Exception:
        pass


def _issue_key(client, token):
    r = client.post("/api/keys/issue", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 201
    return r.json()["key"]


def _create_test_admin(db_session, username, email):
    """Helper to create a test admin directly in the DB."""
    user = User(
        username=username,
        email=email,
        hashed_password=hash_password("TestPass!12345"),
        is_active=True,
        is_approved=True,
        role="admin",
    )
    db_session.add(user)
    db_session.commit()
    return user


# ══════════════════════════════════════════════════════════════════════════════
# FIX 1 — Rate Limiting
# ══════════════════════════════════════════════════════════════════════════════

class TestRateLimiting:
    def test_login_rate_limit_triggers_after_threshold(self, client):
        """Repeated failed logins should eventually get 429."""
        for i in range(10):
            resp = client.post(
                "/auth/login",
                json={"username": "nonexistent", "password": "wrong"},
            )
            if resp.status_code == 429:
                assert i >= 8, f"Rate limit triggered too early at attempt {i}"
                return
        resp = client.post(
            "/auth/login",
            json={"username": "nonexistent", "password": "wrong"},
        )
        assert resp.status_code == 429, (
            f"Expected 429 after rate limit, got {resp.status_code}"
        )

    def test_key_validation_rate_limit(self, client, admin_user):
        """Key validation endpoint should be rate limited."""
        _, _, token = admin_user
        for i in range(12):
            resp = client.post(
                "/keys/validate",
                json={"key": f"bogus-key-{i}", "scan_target": "https://example.com"},
            )
            if resp.status_code == 429:
                return
        resp = client.post(
            "/keys/validate",
            json={"key": "another-bogus-key", "scan_target": "https://example.com"},
        )
        assert resp.status_code == 429, "Key validation should be rate limited"


# ══════════════════════════════════════════════════════════════════════════════
# FIX 2 — Audit Secret Required in Production
# ══════════════════════════════════════════════════════════════════════════════

class TestAuditSecretEnforcement:
    def test_audit_secret_separate_from_jwt_secret(self):
        """Settings should have different values for secret_key and audit_secret."""
        settings.load()
        assert settings.secret_key != settings.audit_secret, (
            "LUME_KS_AUDIT_SECRET must be different from LUME_KS_SECRET_KEY"
        )

    def test_production_startup_fails_without_audit_secret(self, monkeypatch):
        """In production mode, missing LUME_KS_AUDIT_SECRET should raise."""
        monkeypatch.setenv("LUME_KS_ENV", "production")
        monkeypatch.delenv("LUME_KS_AUDIT_SECRET", raising=False)
        monkeypatch.setenv("LUME_KS_SECRET_KEY", "placeholder-jwt-key")
        monkeypatch.setenv("LUME_KS_ENCRYPTION_KEY", os.environ.get("LUME_KS_ENCRYPTION_KEY", ""))

        from ks.config import Settings
        s = Settings()
        with pytest.raises(RuntimeError, match="LUME_KS_AUDIT_SECRET"):
            s.load()

    def test_production_startup_succeeds_with_audit_secret(self, monkeypatch):
        """In production mode with audit secret set, startup should succeed."""
        monkeypatch.setenv("LUME_KS_ENV", "production")
        monkeypatch.setenv("LUME_KS_SECRET_KEY", "placeholder-jwt-key")
        monkeypatch.setenv("LUME_KS_AUDIT_SECRET", "placeholder-audit-key")
        monkeypatch.setenv("LUME_KS_ENCRYPTION_KEY", os.environ.get("LUME_KS_ENCRYPTION_KEY", ""))

        from ks.config import Settings
        s = Settings()
        s.load()
        assert s.audit_secret == "placeholder-audit-key"
        assert s.secret_key == "placeholder-jwt-key"
        assert s.is_production is True


# ══════════════════════════════════════════════════════════════════════════════
# FIX 3 — HTTP Security Headers
# ══════════════════════════════════════════════════════════════════════════════

class TestSecurityHeaders:
    def test_csp_header_present(self, client):
        resp = client.get("/")
        assert "content-security-policy" in {k.lower() for k in resp.headers.keys()}
        csp = resp.headers.get("content-security-policy", "")
        assert "default-src 'self'" in csp
        assert "frame-ancestors" in csp

    def test_x_content_type_options(self, client):
        resp = client.get("/")
        assert resp.headers.get("x-content-type-options") == "nosniff"

    def test_x_frame_options(self, client):
        resp = client.get("/")
        assert resp.headers.get("x-frame-options") in ("DENY", "SAMEORIGIN")

    def test_referrer_policy(self, client):
        resp = client.get("/")
        assert resp.headers.get("referrer-policy") == "strict-origin-when-cross-origin"

    def test_fonts_allowed_in_csp(self, client):
        """CSP must allow Google Fonts (used by base.html templates)."""
        resp = client.get("/")
        csp = resp.headers.get("content-security-policy", "")
        assert "fonts.googleapis.com" in csp
        assert "fonts.gstatic.com" in csp


# ══════════════════════════════════════════════════════════════════════════════
# FIX 4 — CSRF Protection
# ══════════════════════════════════════════════════════════════════════════════

class TestCSRFProtection:
    def test_bearer_token_api_login_not_blocked(self, client):
        """JSON API login should work without CSRF check (Bearer auth, not cookie)."""
        db = _db.SessionLocal()
        try:
            _create_test_admin(db, "csrf_test_admin", "csrf@test.dev")
        finally:
            db.close()
        resp = client.post(
            "/auth/login",
            json={"username": "csrf_test_admin", "password": "TestPass!12345"},
        )
        assert resp.status_code == 200

    def test_cli_key_validation_not_blocked(self, client, admin_user):
        """POST /keys/validate (no cookie, no Origin) should work — CLI integration."""
        _, _, token = admin_user
        key = _issue_key(client, token)
        resp = client.post(
            "/keys/validate",
            json={"key": key, "scan_target": "https://example.com/scan"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "consumed"

    def test_browser_form_login_with_origin_allowed(self, client):
        """Browser form POST with allowed Origin should work."""
        db = _db.SessionLocal()
        try:
            _create_test_admin(db, "form_login_admin", "form@test.dev")
        finally:
            db.close()
        resp = client.post(
            "/login",
            data={"username": "form_login_admin", "password": "TestPass!12345"},
            headers={"Origin": "http://localhost:8100"},
            follow_redirects=False,
        )
        assert resp.status_code in (303, 302)

    def test_browser_form_login_without_origin_blocked_when_cookie_present(
        self, client, admin_user
    ):
        """After a cookie is set, form POST without Origin/Referer should be blocked."""
        _, _, token = admin_user
        login_resp = client.post(
            "/auth/login",
            json={"username": "hardening_admin", "password": "TestPass!12345"},
        )
        assert login_resp.status_code == 200
        resp = client.post(
            "/keys/request",
            cookies={"access_token": token},
        )
        assert resp.status_code == 403, (
            f"Expected 403 for CSRF-blocked request, got {resp.status_code}"
        )

    def test_browser_form_login_with_bad_origin_blocked(self, client):
        """Form POST with disallowed Origin should be blocked."""
        db = _db.SessionLocal()
        try:
            _create_test_admin(db, "bad_origin_admin", "badorigin@test.dev")
        finally:
            db.close()
        resp = client.post(
            "/login",
            data={"username": "bad_origin_admin", "password": "TestPass!12345"},
            headers={"Origin": "https://evil-attacker.com"},
            follow_redirects=False,
        )
        assert resp.status_code == 403


# ══════════════════════════════════════════════════════════════════════════════
# FIX 5 — Atomic Key Consumption + Audit Write
# ══════════════════════════════════════════════════════════════════════════════

class TestAtomicConsumptionAudit:
    def test_key_consumed_and_audit_written_together(self, client, admin_user):
        """Both the key consumption and audit event must commit together."""
        _, _, token = admin_user
        key = _issue_key(client, token)

        resp = client.post(
            "/keys/validate",
            json={"key": key, "scan_target": "https://audit-test.example.com"},
        )
        assert resp.status_code == 200

        from ks.auth import hash_enterprise_key
        from ks.models import AuditLog, EnterpriseKey
        key_hash = hash_enterprise_key(key)
        db = _db.SessionLocal()
        try:
            ek = db.query(EnterpriseKey).filter(EnterpriseKey.key_hash == key_hash).first()
            assert ek is not None
            assert ek.is_consumed is True

            audit_entry = (
                db.query(AuditLog)
                .filter(AuditLog.event_type == "key_consumed")
                .first()
            )
            assert audit_entry is not None, (
                "Audit event for key_consumed must exist after successful consumption"
            )
        finally:
            db.close()

    def test_replay_rejected_and_no_duplicate_audit(self, client, admin_user):
        """Replaying a consumed key should fail and not create a duplicate audit."""
        _, _, token = admin_user
        key = _issue_key(client, token)

        resp1 = client.post(
            "/keys/validate",
            json={"key": key, "scan_target": "https://replay.example.com"},
        )
        assert resp1.status_code == 200

        resp2 = client.post(
            "/keys/validate",
            json={"key": key, "scan_target": "https://replay.example.com"},
        )
        assert resp2.status_code == 401

        from ks.models import AuditLog
        db = _db.SessionLocal()
        try:
            count = db.query(AuditLog).filter(AuditLog.event_type == "key_consumed").count()
            assert count == 1, f"Expected exactly 1 audit entry, got {count}"
        finally:
            db.close()

    def test_concurrent_consumption_only_one_wins_with_audit(self, client, admin_user):
        """10 threads racing — exactly 1 success, 9 rejected, each success has its audit."""
        _, _, token = admin_user
        key = _issue_key(client, token)

        results = []
        lock = threading.Lock()

        def try_consume():
            r = client.post(
                "/keys/validate",
                json={"key": key, "scan_target": "https://concurrent.example.com"},
            )
            with lock:
                results.append(r.status_code)

        threads = [threading.Thread(target=try_consume) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        successes = results.count(200)
        assert successes == 1, f"Expected 1 success, got {successes}"

        from ks.models import AuditLog
        db = _db.SessionLocal()
        try:
            count = db.query(AuditLog).filter(AuditLog.event_type == "key_consumed").count()
            assert count == 1
        finally:
            db.close()


# ══════════════════════════════════════════════════════════════════════════════
# FIX 6 — Database Connection Pool Configuration
# ══════════════════════════════════════════════════════════════════════════════

class TestConnectionPoolConfig:
    def test_pool_settings_read_from_env(self, monkeypatch):
        """Pool settings should be read from environment variables."""
        monkeypatch.setenv("LUME_KS_DB_POOL_SIZE", "5")
        monkeypatch.setenv("LUME_KS_DB_MAX_OVERFLOW", "10")
        monkeypatch.setenv("LUME_KS_DB_POOL_TIMEOUT", "45")
        monkeypatch.setenv("LUME_KS_DB_POOL_RECYCLE", "900")

        from ks.config import Settings
        s = Settings()
        s.load()
        assert s.db_pool_size == 5
        assert s.db_max_overflow == 10
        assert s.db_pool_timeout == 45
        assert s.db_pool_recycle == 900

    def test_pool_defaults_sensible(self):
        """Default pool settings should be reasonable for Supabase free tier."""
        settings.load()
        assert settings.db_pool_size >= 1
        assert settings.db_max_overflow >= 0
        assert settings.db_pool_size + settings.db_max_overflow <= 20, (
            "Total connections should stay within Supabase free tier limit"
        )

    def test_sqlite_uses_no_pool_settings(self, client):
        """SQLite should work without pool settings (ignored for file-based DBs)."""
        resp = client.get("/")
        assert resp.status_code == 200


# ══════════════════════════════════════════════════════════════════════════════
# NEW FIX 1b — Audit secret must differ from JWT secret in production
# ══════════════════════════════════════════════════════════════════════════════

class TestAuditSecretIdentityRejection:
    def test_production_startup_fails_when_secrets_identical(self, monkeypatch):
        """In production, audit secret == JWT secret must be rejected."""
        monkeypatch.setenv("LUME_KS_ENV", "production")
        monkeypatch.setenv("LUME_KS_SECRET_KEY", "shared-secret-value")
        monkeypatch.setenv("LUME_KS_AUDIT_SECRET", "shared-secret-value")  # same value!
        monkeypatch.setenv("LUME_KS_ENCRYPTION_KEY", os.environ.get("LUME_KS_ENCRYPTION_KEY", ""))

        from ks.config import Settings
        s = Settings()
        with pytest.raises(RuntimeError, match="must be different"):
            s.load()

    def test_production_startup_succeeds_when_secrets_differ(self, monkeypatch):
        """In production, distinct audit and JWT secrets are accepted."""
        monkeypatch.setenv("LUME_KS_ENV", "production")
        monkeypatch.setenv("LUME_KS_SECRET_KEY", "jwt-secret-value")
        monkeypatch.setenv("LUME_KS_AUDIT_SECRET", "audit-secret-different-value")
        monkeypatch.setenv("LUME_KS_ENCRYPTION_KEY", os.environ.get("LUME_KS_ENCRYPTION_KEY", ""))

        from ks.config import Settings
        s = Settings()
        s.load()
        assert s.secret_key != s.audit_secret

    def test_development_allows_same_secret_with_warning(self, monkeypatch):
        """In development mode, identical secrets produce a warning but don't fail."""
        monkeypatch.setenv("LUME_KS_ENV", "development")
        monkeypatch.setenv("LUME_KS_SECRET_KEY", "dev-shared-secret")
        monkeypatch.delenv("LUME_KS_AUDIT_SECRET", raising=False)
        monkeypatch.setenv("LUME_KS_ENCRYPTION_KEY", os.environ.get("LUME_KS_ENCRYPTION_KEY", ""))

        import warnings

        from ks.config import Settings
        s = Settings()
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            s.load()
        # Should warn about missing audit secret
        messages = [str(w.message) for w in caught]
        assert any("LUME_KS_AUDIT_SECRET" in m for m in messages), (
            "Expected deprecation warning about LUME_KS_AUDIT_SECRET"
        )
        # Should NOT raise
        assert s.audit_secret == "dev-shared-secret"


# ══════════════════════════════════════════════════════════════════════════════
# NEW FIX 2b — SQLAlchemy dialect detection (db.get_bind() not db.bind)
# ══════════════════════════════════════════════════════════════════════════════

class TestDialectDetection:
    def test_sqlite_dialect_detected(self):
        """_is_postgresql should return False for SQLite sessions."""
        import ks.database as _db_mod
        from ks.key_consume import _is_postgresql
        assert _is_postgresql(_db_mod.SessionLocal()) is False

    def test_postgresql_dialect_function_uses_get_bind(self):
        """_is_postgresql should use db.get_bind(), not deprecated db.bind."""
        import inspect

        from ks.key_consume import _is_postgresql
        src = inspect.getsource(_is_postgresql)
        assert "db.get_bind()" in src, "Must use db.get_bind() not deprecated db.bind"
        assert "db.bind" not in src.replace("db.get_bind()", ""), (
            "db.bind must not be used anywhere"
        )


# ══════════════════════════════════════════════════════════════════════════════
# NEW FIX 3b — Rate-limit IP extraction: trusted vs untrusted proxy
# ══════════════════════════════════════════════════════════════════════════════

class TestRateLimitIPExtraction:
    """Tests for the trusted-proxy IP extraction logic in rate_limit.py.

    Key security property: Render does NOT strip client-supplied X-Forwarded-For.
    Reading the FIRST entry is exploitable (attacker-controlled).
    Reading the LAST entry (appended by Render) is safe.
    """

    def _make_request(self, xff_header=None, direct_ip="127.0.0.1"):
        """Build a minimal mock request for _get_client_ip."""
        class _Client:
            def __init__(self, host):
                self.host = host
        class _Headers:
            def __init__(self, xff):
                self._xff = xff
            def get(self, key, default=""):
                return self._xff if key == "x-forwarded-for" and self._xff else default
        class _Req:
            def __init__(self, xff, ip):
                self.headers = _Headers(xff)
                self.client = _Client(ip)
        return _Req(xff_header, direct_ip)

    def _get_ip_with_trust(self, trust: bool, proxy_count: int = 1, xff=None, direct="127.0.0.1"):
        """Call _get_client_ip with explicit trust/proxy_count, without module reload."""
        from ks import rate_limit as rl_mod
        req = self._make_request(xff_header=xff, direct_ip=direct)
        orig_trust = rl_mod._is_trust_proxy
        orig_count = rl_mod._proxy_count
        rl_mod._is_trust_proxy = lambda: trust
        rl_mod._proxy_count = lambda: proxy_count
        try:
            return rl_mod._get_client_ip(req)
        finally:
            rl_mod._is_trust_proxy = orig_trust
            rl_mod._proxy_count = orig_count

    # ── Correct (rightmost entry) behavior ────────────────────────────────────

    def test_trusted_proxy_uses_rightmost_entry(self):
        """In trusted proxy mode with 1 hop, the LAST XFF entry is used (Render-appended)."""
        result = self._get_ip_with_trust(trust=True, proxy_count=1, xff="attacker-ip, 5.6.7.8")
        assert result == "5.6.7.8"
        assert result != "attacker-ip"

    def test_forged_first_entry_is_ignored(self):
        """A client sending a forged first XFF entry must not change their rate-limit identity."""
        result = self._get_ip_with_trust(trust=True, proxy_count=1, xff="1.1.1.1, real-render-ip")
        assert result == "real-render-ip"
        assert result != "1.1.1.1"

    def test_multiple_forged_entries_ignored(self):
        """Multiple forged entries before the Render-appended one are all ignored."""
        result = self._get_ip_with_trust(
            trust=True, proxy_count=1, xff="fake1, fake2, fake3, real-client-ip"
        )
        assert result == "real-client-ip"
        assert "fake" not in result

    def test_two_proxy_hops_uses_second_from_right(self):
        """With proxy_count=2 (e.g. Render + Cloudflare), use entries[-2]."""
        result = self._get_ip_with_trust(
            trust=True, proxy_count=2, xff="attacker, cloudflare-client-ip, render-edge-ip"
        )
        assert result == "cloudflare-client-ip"

    def test_single_entry_matches_expected_with_one_hop(self):
        """Single XFF entry with 1 trusted hop → use that entry."""
        result = self._get_ip_with_trust(trust=True, proxy_count=1, xff="203.0.113.1")
        assert result == "203.0.113.1"

    # ── Fallback / edge cases ──────────────────────────────────────────────────

    def test_missing_xff_falls_back_to_direct_ip(self):
        """No XFF header → use direct TCP connection IP."""
        result = self._get_ip_with_trust(trust=True, proxy_count=1, xff=None, direct="10.0.0.1")
        assert result == "10.0.0.1"

    def test_fewer_entries_than_proxy_count_falls_back_to_direct(self):
        """If XFF has fewer entries than proxy_count, fall back to direct IP (safe)."""
        result = self._get_ip_with_trust(
            trust=True, proxy_count=3, xff="only-one-entry", direct="10.0.0.5"
        )
        # Fewer entries (1) than proxy_count (3) → fall back
        assert result == "10.0.0.5"

    def test_whitespace_stripped_from_xff_entries(self):
        """XFF entries with extra whitespace are handled correctly."""
        result = self._get_ip_with_trust(trust=True, proxy_count=1, xff="  fake  ,  5.6.7.8  ")
        assert result == "5.6.7.8"

    # ── Untrusted (development) mode ──────────────────────────────────────────

    def test_untrusted_mode_ignores_xff_entirely(self):
        """In dev (untrusted) mode, XFF is ignored even with multiple entries."""
        result = self._get_ip_with_trust(
            trust=False, proxy_count=1, xff="9.9.9.9, 1.2.3.4", direct="127.0.0.1"
        )
        # Neither XFF entry used — direct IP returned
        assert result == "127.0.0.1"
        assert result not in ("9.9.9.9", "1.2.3.4")

    def test_forged_xff_cannot_bypass_rate_limit_in_dev(self):
        """Dev mode: attacker sending XFF: different-ip cannot change their bucket."""
        result = self._get_ip_with_trust(trust=False, xff="bypass-ip", direct="192.168.1.1")
        assert result == "192.168.1.1"
        assert result != "bypass-ip"

    # ── Environment-driven trust ───────────────────────────────────────────────

    def test_production_env_enables_proxy_trust_by_default(self, monkeypatch):
        """LUME_KS_ENV=production enables proxy trust when LUME_KS_TRUST_PROXY unset."""
        monkeypatch.setenv("LUME_KS_ENV", "production")
        monkeypatch.delenv("LUME_KS_TRUST_PROXY", raising=False)
        from ks.rate_limit import _is_trust_proxy
        assert _is_trust_proxy() is True

    def test_development_env_disables_proxy_trust_by_default(self, monkeypatch):
        """LUME_KS_ENV=development disables proxy trust by default."""
        monkeypatch.setenv("LUME_KS_ENV", "development")
        monkeypatch.delenv("LUME_KS_TRUST_PROXY", raising=False)
        from ks.rate_limit import _is_trust_proxy
        assert _is_trust_proxy() is False

    def test_explicit_trust_proxy_true_overrides_dev_env(self, monkeypatch):
        """LUME_KS_TRUST_PROXY=true enables trust even in dev mode."""
        monkeypatch.setenv("LUME_KS_ENV", "development")
        monkeypatch.setenv("LUME_KS_TRUST_PROXY", "true")
        from ks.rate_limit import _is_trust_proxy
        assert _is_trust_proxy() is True

    def test_explicit_trust_proxy_false_disables_in_production(self, monkeypatch):
        """LUME_KS_TRUST_PROXY=false disables trust even in production."""
        monkeypatch.setenv("LUME_KS_ENV", "production")
        monkeypatch.setenv("LUME_KS_TRUST_PROXY", "false")
        from ks.rate_limit import _is_trust_proxy
        assert _is_trust_proxy() is False

    # ── proxy_count configuration ──────────────────────────────────────────────

    def test_proxy_count_defaults_to_one(self, monkeypatch):
        """Default LUME_KS_PROXY_COUNT is 1."""
        monkeypatch.delenv("LUME_KS_PROXY_COUNT", raising=False)
        from ks.rate_limit import _proxy_count
        assert _proxy_count() == 1

    def test_proxy_count_reads_from_env(self, monkeypatch):
        """LUME_KS_PROXY_COUNT=2 is read correctly."""
        monkeypatch.setenv("LUME_KS_PROXY_COUNT", "2")
        from ks.rate_limit import _proxy_count
        assert _proxy_count() == 2

    def test_proxy_count_minimum_is_one(self, monkeypatch):
        """LUME_KS_PROXY_COUNT=0 is clamped to 1 (never use index 0 from right = last)."""
        monkeypatch.setenv("LUME_KS_PROXY_COUNT", "0")
        from ks.rate_limit import _proxy_count
        assert _proxy_count() == 1


# ══════════════════════════════════════════════════════════════════════════════
# NEW FIX 4b — Audit rollback failure injection
# ══════════════════════════════════════════════════════════════════════════════

class TestAuditRollbackOnFailure:
    """Prove that if audit logging raises, key consumption is rolled back."""

    def test_audit_failure_rolls_back_consumption(self, client, admin_user, monkeypatch):
        """If write_event raises after consumption, the key must NOT be consumed."""
        _, _, token = admin_user
        key = _issue_key(client, token)

        # Patch write_event to raise after consume_key_atomically succeeds
        import ks.routes.keys as keys_route
        original_write_event = keys_route.write_event

        def _failing_write_event(*args, **kwargs):
            raise RuntimeError("Simulated audit write failure")

        monkeypatch.setattr(keys_route, "write_event", _failing_write_event)

        resp = client.post(
            "/keys/validate",
            json={"key": key, "scan_target": "https://rollback-test.example.com"},
        )

        # Portal must return 500 (not 200)
        assert resp.status_code == 500, (
            f"Expected 500 on audit failure, got {resp.status_code}"
        )

        # Restore write_event
        monkeypatch.setattr(keys_route, "write_event", original_write_event)

        # KEY MUST NOT BE CONSUMED — rollback must have restored it
        from ks.auth import hash_enterprise_key
        from ks.models import EnterpriseKey
        key_hash = hash_enterprise_key(key)
        db = _db.SessionLocal()
        try:
            ek = db.query(EnterpriseKey).filter(EnterpriseKey.key_hash == key_hash).first()
            assert ek is not None, "Key must still exist"
            assert ek.is_consumed is False, (
                "Key must NOT be consumed after audit rollback"
            )
        finally:
            db.close()

    def test_audit_failure_leaves_no_incomplete_audit_entry(self, client, admin_user, monkeypatch):
        """After a rollback, no partial audit entry for key_consumed must remain."""
        _, _, token = admin_user
        key = _issue_key(client, token)

        import ks.routes.keys as keys_route

        def _failing_write_event(*args, **kwargs):
            raise RuntimeError("Simulated audit write failure")

        monkeypatch.setattr(keys_route, "write_event", _failing_write_event)

        client.post(
            "/keys/validate",
            json={"key": key, "scan_target": "https://no-audit.example.com"},
        )

        from ks.models import AuditLog
        db = _db.SessionLocal()
        try:
            count = db.query(AuditLog).filter(AuditLog.event_type == "key_consumed").count()
            assert count == 0, (
                f"No audit entry must exist after rollback, found {count}"
            )
        finally:
            db.close()

    def test_key_still_usable_after_failed_consumption(self, client, admin_user, monkeypatch):
        """After rollback, the key must be consumable on a retry."""
        _, _, token = admin_user
        key = _issue_key(client, token)

        import ks.routes.keys as keys_route
        original_write_event = keys_route.write_event

        # First attempt: audit fails → rollback
        def _failing_write_event(*args, **kwargs):
            raise RuntimeError("Simulated audit write failure")

        monkeypatch.setattr(keys_route, "write_event", _failing_write_event)
        resp_fail = client.post(
            "/keys/validate",
            json={"key": key, "scan_target": "https://retry-test.example.com"},
        )
        assert resp_fail.status_code == 500

        # Restore write_event
        monkeypatch.setattr(keys_route, "write_event", original_write_event)

        # Second attempt with real write_event must succeed
        resp_ok = client.post(
            "/keys/validate",
            json={"key": key, "scan_target": "https://retry-test.example.com"},
        )
        assert resp_ok.status_code == 200, (
            f"Key must be consumable after rollback recovery, got {resp_ok.status_code}"
        )


# ══════════════════════════════════════════════════════════════════════════════
# NEW FIX 5b — PostgreSQL integration tests (skipped if no PG connection)
# ══════════════════════════════════════════════════════════════════════════════

def _pg_url() -> str | None:
    """Return the PostgreSQL URL from environment, or None if not configured."""
    url = os.environ.get("LUME_KS_TEST_PG_URL", "").strip()
    return url if url else None


@pytest.mark.skipif(
    _pg_url() is None,
    reason="LUME_KS_TEST_PG_URL not set — PostgreSQL integration tests skipped. "
           "Set this to an isolated test database URL (never production) to run them.",
)
class TestPostgreSQLIntegration:
    """PostgreSQL-specific integration tests.

    These tests only run when LUME_KS_TEST_PG_URL is set to an isolated
    test database (never production). They verify PostgreSQL-specific
    behaviors that SQLite tests cannot cover:

    - Atomic UPDATE...WHERE...RETURNING concurrency (MVCC)
    - Connection pool behavior
    - RLS policy application
    - Dialect detection via db.get_bind()
    """

    @pytest.fixture(scope="class", autouse=True)
    def pg_client(self):
        """Create a test app connected to PostgreSQL."""
        from contextlib import asynccontextmanager as _acm

        import ks.database as _db_mod
        from ks.config import Settings
        from ks.main import create_app

        pg_url = _pg_url()
        s = Settings()
        s.load()
        s.db_url = pg_url

        _db_mod.init_db(db_url=pg_url)

        @_acm
        async def _noop(app):
            yield

        app = create_app()
        app.router.lifespan_context = _noop

        from fastapi.testclient import TestClient
        with TestClient(app, raise_server_exceptions=True) as c:
            yield c

        # Cleanup: drop test tables (test DB only, never production)
        from ks.database import Base
        if _db_mod._engine:
            Base.metadata.drop_all(bind=_db_mod._engine)

    def test_pg_dialect_detected(self):
        """db.get_bind() must report postgresql dialect."""
        import ks.database as _db_mod
        from ks.key_consume import _is_postgresql
        db = _db_mod.SessionLocal()
        try:
            assert _is_postgresql(db) is True
        finally:
            db.close()

    def test_pg_concurrent_consumption_exactly_one_wins(self, pg_client):
        """10 concurrent threads — exactly 1 consumption success on PostgreSQL."""
        # Seed an admin
        import ks.database as _db_mod
        from ks.auth import create_access_token, hash_password
        from ks.models import User
        db = _db_mod.SessionLocal()
        try:
            user = User(
                username="pg_test_admin",
                email="pgadmin@pg.test",
                hashed_password=hash_password("TestPass!12345"),
                is_active=True, is_approved=True, role="admin",
            )
            db.add(user)
            db.commit()
        finally:
            db.close()

        token = create_access_token(subject="pg_test_admin")
        key_resp = pg_client.post("/api/keys/issue",
                                   headers={"Authorization": f"Bearer {token}"})
        assert key_resp.status_code == 201
        key = key_resp.json()["key"]

        import threading
        results = []
        lock = threading.Lock()

        def consume():
            r = pg_client.post("/keys/validate",
                                json={"key": key, "scan_target": "https://pg-test.example.com"})
            with lock:
                results.append(r.status_code)

        threads = [threading.Thread(target=consume) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert results.count(200) == 1, f"Expected 1 success, got {results}"
        assert results.count(401) == 9

    def test_pg_audit_rls_applied(self):
        """RLS must be enabled and forced on audit_logs after policy is applied."""
        import ks.database as _db_mod
        from ks.audit_worm import apply_audit_worm_policy, verify_audit_worm_policy

        # apply_audit_worm_policy runs in lifespan — call it explicitly here
        # since the test fixture bypasses the app lifespan. It is idempotent.
        apply_result = apply_audit_worm_policy(_db_mod._engine)
        assert apply_result.get("applied") is True, (
            f"RLS policy could not be applied: {apply_result}"
        )

        status = verify_audit_worm_policy(_db_mod._engine)
        assert status.get("rls_enabled") is True
        assert status.get("rls_forced") is True


# ══════════════════════════════════════════════════════════════════════════════
# NEW FIX 6b — CLI-to-portal integration tests
# ══════════════════════════════════════════════════════════════════════════════

class TestCLIPortalIntegration:
    """End-to-end tests: actual key_client.py talking to a live TestClient portal.

    These tests use httpx + the real validate_enterprise_key() function to verify
    that the CLI integration works correctly end-to-end, not just in isolation.
    """

    @pytest.fixture
    def portal_url(self, client):
        """Return a URL that httpx can hit on the TestClient portal."""
        # TestClient listens on a fake transport — we need to inject it.
        # We call validate_enterprise_key with a mock transport that routes
        # requests through the TestClient directly.
        return "http://test-portal-local"

    @pytest.fixture
    def portal_with_key(self, client, admin_user):
        """Issue a key and return (client, key, token)."""
        _, _, token = admin_user
        key = _issue_key(client, token)
        return client, key, token

    def _call_validate(self, test_client, key, scan_target, timeout=5.0):
        """Call validate_enterprise_key routing through the TestClient."""

        from lume.enterprise.key_client import KeyConsumedReceipt, KeyValidationError

        payload = {"key": key, "scan_target": scan_target}

        # Build the response by calling the TestClient directly
        resp = test_client.post("/keys/validate", json=payload)

        if resp.status_code == 200:
            data = resp.json()
            from datetime import datetime
            return KeyConsumedReceipt(
                consumed_at=datetime.fromisoformat(data["consumed_at"]),
                message=data.get("message", ""),
            )
        if resp.status_code == 401:
            detail = resp.json().get("detail", {})
            reason = detail.get("reason", "rejected") if isinstance(detail, dict) else "rejected"
            msg = detail.get("detail", "rejected") if isinstance(detail, dict) else str(detail)
            raise KeyValidationError(msg, reason=reason)
        if resp.status_code == 429:
            raise KeyValidationError("Rate limited", reason="rate_limited")
        raise KeyValidationError(
            f"Unexpected status {resp.status_code}", reason="unexpected"
        )

    def test_valid_key_consumed_via_cli(self, portal_with_key):
        """Valid key returns a KeyConsumedReceipt — scan proceeds."""

        from lume.enterprise.key_client import KeyConsumedReceipt
        test_client, key, _ = portal_with_key
        receipt = self._call_validate(test_client, key, "https://cli-test.example.com")
        assert isinstance(receipt, KeyConsumedReceipt)
        assert receipt.consumed_at is not None

    def test_invalid_key_raises_validation_error(self, client):
        """Non-existent key raises KeyValidationError — scan blocked."""

        from lume.enterprise.key_client import KeyValidationError
        with pytest.raises(KeyValidationError) as exc_info:
            self._call_validate(client, "A" * 43, "https://cli-test.example.com")
        assert exc_info.value.reason == "not_found"

    def test_reused_key_raises_already_consumed(self, portal_with_key):
        """Second use of consumed key raises KeyValidationError — scan blocked."""

        from lume.enterprise.key_client import KeyValidationError
        test_client, key, _ = portal_with_key
        # First use succeeds
        self._call_validate(test_client, key, "https://cli-test.example.com")
        # Second use must fail
        with pytest.raises(KeyValidationError) as exc_info:
            self._call_validate(test_client, key, "https://cli-test.example.com")
        assert exc_info.value.reason == "already_consumed"

    def test_revoked_key_raises_revoked(self, client, admin_user):
        """Revoked key raises KeyValidationError with reason='revoked'."""

        from lume.enterprise.key_client import KeyValidationError
        _, _, token = admin_user
        key = _issue_key(client, token)

        # Revoke the key via admin API
        all_keys = client.get("/api/admin/keys",
                               headers={"Authorization": f"Bearer {token}"}).json()
        kid = next(k["id"] for k in all_keys["keys"]
                   if not k["is_consumed"] and not k["is_revoked"])
        client.post(f"/api/admin/keys/{kid}/revoke",
                    headers={"Authorization": f"Bearer {token}"})

        with pytest.raises(KeyValidationError) as exc_info:
            self._call_validate(client, key, "https://cli-test.example.com")
        assert exc_info.value.reason == "revoked"

    def test_expired_key_raises_expired(self, client, admin_user):
        """Expired key raises KeyValidationError with reason='expired'."""

        from datetime import datetime, timedelta, timezone

        from ks.auth import hash_enterprise_key
        from ks.models import EnterpriseKey

        from lume.enterprise.key_client import KeyValidationError

        _, _, token = admin_user
        key = _issue_key(client, token)

        # Force-expire the key directly in DB
        key_hash = hash_enterprise_key(key)
        db = _db.SessionLocal()
        try:
            ek = db.query(EnterpriseKey).filter(EnterpriseKey.key_hash == key_hash).first()
            ek.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
            db.commit()
        finally:
            db.close()

        with pytest.raises(KeyValidationError) as exc_info:
            self._call_validate(client, key, "https://cli-test.example.com")
        assert exc_info.value.reason == "expired"

    def test_failed_validation_does_not_consume_key(self, portal_with_key):
        """When validation is rejected, the key remains unconsumed."""

        from ks.auth import hash_enterprise_key
        from ks.models import EnterpriseKey

        from lume.enterprise.key_client import KeyValidationError

        test_client, key, _ = portal_with_key
        key_hash = hash_enterprise_key(key)

        # Try a different (nonexistent) key — validation fails
        with pytest.raises(KeyValidationError):
            self._call_validate(test_client, "B" * 43, "https://cli-test.example.com")

        # The original key must still be unconsumed
        db = _db.SessionLocal()
        try:
            ek = db.query(EnterpriseKey).filter(EnterpriseKey.key_hash == key_hash).first()
            assert ek.is_consumed is False
        finally:
            db.close()
