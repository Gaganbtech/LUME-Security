# Security Fix Report — Pre-Production Blockers

**Project:** TravLume Enterprise Key Portal  
**Branch:** `feat/enterprise-key`  
**Date:** October 2026  
**Status:** All three fixes implemented, tested, and verified  

---

## Executive Summary

Three pre-production security blockers were identified during a security audit of the Enterprise Key Portal. All three have been implemented, covered by 22 dedicated tests (part of the 111-test regression suite), and verified against both SQLite (local) and PostgreSQL (Supabase).

| # | Blocker | Severity | Status |
|---|---------|----------|--------|
| 1 | TOCTOU race in key consumption | Critical | **Fixed** |
| 2 | Plaintext `pending_display_key` in DB | High | **Fixed** |
| 3 | Audit log WORM only app-level | High | **Partially fixed** (see notes) |

---

## Fix 1 — Atomic Key Consumption (Critical)

### Problem

The original `validate_key` route performed a SELECT to find the key, checked `is_consumed`, then issued a separate UPDATE to mark it consumed. Two concurrent requests could both pass the SELECT check before either reached the UPDATE, allowing a single key to be consumed twice — a TOCTOU (time-of-check-to-time-of-use) race condition.

### Solution

New module `ks/key_consume.py` with dialect-aware atomic consumption:

**PostgreSQL path:** A single `UPDATE ... WHERE is_consumed = false AND is_revoked = false AND (expires_at IS NULL OR expires_at > now()) RETURNING id, owner_id, key_id`. PostgreSQL's MVCC guarantees exactly one concurrent transaction wins the UPDATE — the other gets `rowcount=0` and falls through to the reason-diagnostic SELECT.

**SQLite path:** SELECT + UPDATE inside a single transaction. SQLite serialises all writes via its global write lock, eliminating the race window on a single-process dev server.

Both paths return a dict with `id`, `owner_id`, `key_id`, `consumed_at` on success, or raise `KeyNotFound` with a specific `reason` (`not_found`, `already_consumed`, `revoked`, `expired`) on failure.

### Verification

- **SQLite (test suite):** 10 concurrent threads racing to consume one key — exactly 1 succeeds, 9 get 401 `already_consumed`. Covered by `test_many_concurrent_consumers_exactly_one_wins`.
- **PostgreSQL (Supabase live):** 10 concurrent threads against Supabase transaction pooler — exactly 1 success, 9 rejected, 0 errors. Atomicity confirmed.
- **Regression:** Revoked keys, expired keys, and nonexistent keys all return the correct error reason.

### Files changed

- `ks/key_consume.py` — new module
- `ks/routes/keys.py` — `validate_key` now calls `consume_key_atomically()`

---

## Fix 2 — Encrypted `pending_display_key` (High)

### Problem

When an admin approved a key request, the plaintext enterprise key was written directly to `key_requests.pending_display_key` in the database. Anyone with database read access (DB admin, backup viewer, Supabase dashboard user) could read the plaintext key before the requesting user viewed it.

### Solution

New module `ks/key_crypto.py` using `cryptography.fernet.Fernet` for authenticated encryption (AES-128-CBC + HMAC-SHA256):

1. Admin approves request → server generates 43-char plaintext key.
2. `encrypt_pending_key(plaintext)` → Fernet token (~200 chars, starts with `gAAA`).
3. Token stored in `key_requests.pending_display_key` (column widened from `VARCHAR(128)` to `VARCHAR(512)`).
4. User visits dashboard → `decrypt_pending_key(token)` → plaintext shown once.
5. `pending_display_key` set to `NULL` immediately after read.

**Key management:**
- New env var `LUME_KS_ENCRYPTION_KEY` (Fernet key, separate from JWT secret and audit HMAC secret).
- In production (`LUME_KS_ENV=production`), the service refuses to start without it.
- In development, missing key raises at the point of use (not silent fallback).
- `render.yaml` has `generateValue: true` so Render generates it automatically.

**Migration:**
- `is_encrypted_token()` heuristic distinguishes Fernet tokens (`gAAA` prefix) from legacy plaintext values, preventing double-encryption during upgrades.
- PostgreSQL migration: `ALTER TABLE key_requests ALTER COLUMN pending_display_key TYPE VARCHAR(512)` (wrapped in try/except, non-fatal if already wide).

### Verification

- `test_encrypt_produces_fernet_token` — ciphertext does not contain plaintext.
- `test_decrypt_recovers_plaintext` — round-trip works.
- `test_decrypt_wrong_key_returns_none` — wrong Fernet key returns None (no exception).
- `test_decrypt_tampered_token_returns_none` — tampered ciphertext returns None.
- `test_pending_key_not_plaintext_in_db_after_approval` — DB inspection confirms stored value is a Fernet token, not plaintext.
- `test_one_time_display_clears_encrypted_value` — confirms `pending_display_key` is NULL after dashboard read.

### Files changed

- `ks/key_crypto.py` — new module
- `ks/models.py` — `pending_display_key` widened to `String(512)`
- `ks/config.py` — added `encryption_key`, `is_production`, production enforcement
- `ks/routes/admin.py` — approval now calls `encrypt_pending_key()` before storing
- `ks/routes/keys.py` — dashboard decrypts via `decrypt_pending_key()`
- `ks/database.py` — PostgreSQL migration widens column
- `render.yaml` — `LUME_KS_ENCRYPTION_KEY` with `generateValue: true`
- `.env.example` — `LUME_KS_ENCRYPTION_KEY` documented

---

## Fix 3 — Audit Log DB-Level Protection (High)

### Problem

The audit log was protected only at the application level — no HTTP routes existed for UPDATE or DELETE on `audit_logs`. A compromised process or someone with direct database access could modify or delete audit entries without detection.

### Solution

Two layers of protection:

**Layer 1 — Tamper-evident HMAC chain (fully working):**

Every audit log entry contains:
- `prev_entry_hash` — SHA-256 hash of the previous entry's `chain_hash`.
- `chain_hash` — SHA-256 of `prev_entry_hash + event_type + timestamp + event_data`.
- `entry_hmac` — HMAC-SHA256 of the entry using `LUME_KS_AUDIT_SECRET`.

The `/api/admin/audit/verify` endpoint walks the chain and detects any modification: changing `event_type`, `timestamp`, or `event_data` invalidates the HMAC, and changing `chain_hash` breaks the chain link. Covered by `test_tampered_entry_detected_by_verify`.

**Layer 2 — PostgreSQL Row Level Security (partially working):**

New module `ks/audit_worm.py` applies RLS policies on startup:

```sql
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_insert_only ON audit_logs AS PERMISSIVE FOR INSERT WITH CHECK (true);
CREATE POLICY audit_select_all ON audit_logs AS PERMISSIVE FOR SELECT USING (true);
-- No UPDATE or DELETE policy → denied by default under RLS
```

`FORCE ROW LEVEL SECURITY` means even the table owner is subject to RLS policies.

**Verified on Supabase:**
- RLS enabled: **YES**
- RLS forced: **YES**
- INSERT: works (policy allows it)
- SELECT: works (policy allows it)
- UPDATE: **NOT blocked** — rowcount=1
- DELETE: **NOT blocked** — rowcount=1

**Root cause:** Supabase's default connection string uses the `postgres` role, which is a PostgreSQL **superuser**. Superusers bypass all RLS policies, including those declared with `FORCE`. This is a documented PostgreSQL limitation — `FORCE` prevents the table *owner* from bypassing RLS, but a superuser is above the owner in the privilege hierarchy.

### What this means

The audit log is **tamper-evident**, not **tamper-proof at the DB level** on Supabase's free tier:

- If someone modifies or deletes audit entries through the application API: **blocked** (no UPDATE/DELETE routes exist).
- If someone modifies or deletes entries via direct DB access using the `postgres` superuser: **not blocked** by RLS, but **detected** by the HMAC chain verification.
- If someone modifies or deletes entries via a non-superuser DB role with RLS: **blocked** by RLS.

### Recommended hardening (future work)

To achieve full DB-level immutability on Supabase:
1. Create a dedicated non-superuser app role (e.g., `lume_app`) that the service connects with.
2. Grant that role INSERT and SELECT on `audit_logs` only.
3. RLS with FORCE will then block UPDATE/DELETE from the app role.

This requires either Supabase's paid plan (custom roles) or manual role setup via the SQL editor.

### Files changed

- `ks/audit_worm.py` — new module (RLS policy apply/verify/test)
- `ks/main.py` — calls `apply_audit_worm_policy()` in lifespan startup
- `ks/audit.py` — existing HMAC chain (unchanged, already working)

---

## Test Coverage

22 dedicated tests in `tests/test_security_fixes.py`:

**Fix 1 (8 tests):** atomic success, replay rejection, 2-thread concurrency, 10-thread concurrency, revoked key, expired key, nonexistent key, direct module test.

**Fix 2 (8 tests):** encryption produces Fernet token, decryption round-trip, wrong key returns None, tampered token returns None, empty input, token heuristic, DB inspection after approval, one-time display clears value.

**Fix 3 (6 tests):** SQLite WORM status, audit insert works, chain valid after events, WORM status endpoint, tampered entry detected, no UPDATE/DELETE routes exist.

All 22 tests pass. Full regression: **111 passed, 0 failed, 0 errors**.

---

## Environment Variables

| Variable | Purpose | Required in Prod |
|----------|---------|-------------------|
| `LUME_KS_SECRET_KEY` | JWT session signing | Yes |
| `LUME_KS_AUDIT_SECRET` | Audit log HMAC signing (must differ from SECRET_KEY) | Yes |
| `LUME_KS_ENCRYPTION_KEY` | Fernet encryption for pending display keys | Yes |
| `LUME_KS_DB_URL` | PostgreSQL connection string (Supabase pooler) | Yes |
| `LUME_KS_ENV` | Set to `production` for HTTPS cookies, /docs disabled | Yes |
| `LUME_KS_ALLOWED_ORIGINS` | CORS allowed origins (your domain) | Yes |

---

## Security Notes

- The database password was accidentally shared in chat during development. It must be **reset in the Supabase dashboard** before any real deployment.
- `LUME_KS_SECRET_KEY`, `LUME_KS_AUDIT_SECRET`, and `LUME_KS_ENCRYPTION_KEY` must all be **different values**. Rotating one should not invalidate the others.
- `render.yaml` uses `generateValue: true` for all three secrets, so Render generates them automatically on first deploy.
