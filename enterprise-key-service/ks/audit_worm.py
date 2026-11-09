"""Database-level audit log immutability setup.

What this provides
──────────────────
Application-level restriction (no UPDATE/DELETE routes) prevents accidental
or unauthorised modifications through the application API.

Database-level restriction (PostgreSQL Row Level Security or REVOKE) prevents
modifications even by a compromised application process that has direct DB
access with the application's credentials.

This module contains helpers to apply and verify these restrictions.

Important limitations
─────────────────────
Supabase free tier uses a shared superuser role for the application
connection string (postgres).  A superuser bypasses RLS unless the policy is
declared with FORCE, which prevents even superusers from mutating rows.

The implementation uses RLS with FORCE on PostgreSQL (including Supabase).
On SQLite these protections cannot be applied — SQLite has no row-level
permissions.  The application-level WORM restriction remains in effect.

Never call apply_audit_worm_policy() against a production database without
reviewing the policy SQL first.  This function is idempotent — safe to call
on restart.
"""

import logging

logger = logging.getLogger("ks.audit_worm")

_POLICY_STMTS = [
    # Enable RLS and FORCE it (idempotent — safe to re-run)
    "ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY",
    "ALTER TABLE audit_logs FORCE ROW LEVEL SECURITY",
    # Drop existing policies first so re-runs are safe
    "DROP POLICY IF EXISTS audit_insert_only ON audit_logs",
    "DROP POLICY IF EXISTS audit_select_all ON audit_logs",
    # INSERT: allowed for all roles
    "CREATE POLICY audit_insert_only ON audit_logs AS PERMISSIVE FOR INSERT WITH CHECK (true)",
    # SELECT: allowed for all roles
    "CREATE POLICY audit_select_all ON audit_logs AS PERMISSIVE FOR SELECT USING (true)",
    # UPDATE and DELETE: no policy created → denied by default under RLS
]

_VERIFY_SQL = """
SELECT
    relrowsecurity AS rls_enabled,
    relforcerowsecurity AS rls_forced
FROM pg_class
WHERE relname = 'audit_logs';
"""


def apply_audit_worm_policy(engine) -> dict:
    """Apply PostgreSQL RLS policy to audit_logs.

    Safe to call on every startup — all statements are idempotent.
    Returns dict with 'applied', 'dialect', 'rls_enabled', 'rls_forced'.
    """
    dialect = engine.dialect.name

    if dialect != "postgresql":
        logger.info(
            "Audit WORM policy not applicable for dialect '%s'. "
            "Application-level append-only restriction is active.", dialect
        )
        return {"applied": False, "dialect": dialect, "reason": "not_postgresql"}

    try:
        for stmt in _POLICY_STMTS:
            with engine.begin() as conn:
                conn.execute(__import__("sqlalchemy").text(stmt))

        status = verify_audit_worm_policy(engine)
        logger.info(
            "Audit WORM policy applied: rls_enabled=%s rls_forced=%s",
            status.get("rls_enabled"), status.get("rls_forced")
        )
        return {"applied": True, "dialect": dialect, **status}

    except Exception as exc:
        logger.warning(
            "Could not apply audit WORM policy: %s. "
            "Application-level protection remains active.", exc
        )
        return {"applied": False, "dialect": dialect, "error": str(exc)}


def verify_audit_worm_policy(engine) -> dict:
    """Check whether RLS is enabled and forced on audit_logs."""
    dialect = engine.dialect.name
    if dialect != "postgresql":
        return {"rls_enabled": None, "rls_forced": None, "dialect": dialect}

    try:
        with engine.connect() as conn:
            row = conn.execute(__import__("sqlalchemy").text(_VERIFY_SQL)).fetchone()
        if row:
            return {
                "rls_enabled": row[0],
                "rls_forced": row[1],
                "dialect": dialect,
            }
        return {"rls_enabled": False, "rls_forced": False, "dialect": dialect}
    except Exception as exc:
        return {"rls_enabled": None, "rls_forced": None, "error": str(exc), "dialect": dialect}


def test_audit_worm_enforcement(engine) -> dict:
    """Attempt UPDATE and DELETE on audit_logs with current credentials.

    Returns dict with 'update_blocked', 'delete_blocked'.
    Only valid for PostgreSQL after apply_audit_worm_policy() has been called.

    CAUTION: This inserts a sentinel row and then tries to mutate it.
    Use only against test databases.
    """
    from sqlalchemy import text
    dialect = engine.dialect.name
    if dialect != "postgresql":
        return {"update_blocked": None, "delete_blocked": None,
                "reason": "only_testable_on_postgresql"}

    sentinel_chain = "test_worm_sentinel_" + __import__("secrets").token_hex(8)

    try:
        # Insert a sentinel row
        with engine.begin() as conn:
            conn.execute(text("""
                INSERT INTO audit_logs
                    (event_type, prev_entry_hash, chain_hash, entry_hmac, timestamp)
                VALUES
                    ('worm_test', 'test', :chain, 'test', now())
            """), {"chain": sentinel_chain})

        # Try UPDATE — should be blocked by RLS
        update_blocked = False
        try:
            with engine.begin() as conn:
                conn.execute(text(
                    "UPDATE audit_logs SET event_type = 'tampered' WHERE chain_hash = :c"
                ), {"c": sentinel_chain})
        except Exception:
            update_blocked = True

        # Try DELETE — should be blocked by RLS
        delete_blocked = False
        try:
            with engine.begin() as conn:
                conn.execute(text(
                    "DELETE FROM audit_logs WHERE chain_hash = :c"
                ), {"c": sentinel_chain})
        except Exception:
            delete_blocked = True

        # Clean up sentinel if not blocked (test DB only)
        try:
            with engine.begin() as conn:
                conn.execute(text(
                    "DELETE FROM audit_logs WHERE chain_hash = :c"
                ), {"c": sentinel_chain})
        except Exception:
            pass

        return {"update_blocked": update_blocked, "delete_blocked": delete_blocked}

    except Exception as exc:
        return {"update_blocked": None, "delete_blocked": None, "error": str(exc)}
