# Deployment Guide — TravLume Enterprise Key Portal

## Architecture

```
Browser
    ↓ HTTPS
Cloudflare DNS / WAF
    ↓
Render FastAPI application (enterprise-key-service)
    ↓
Supabase PostgreSQL
```

## Prerequisites

- A Supabase project with PostgreSQL database
- A Render account connected to the team's GitHub repository
- A custom domain (or Render's default `*.onrender.com` domain)
- Cloudflare account for DNS/WAF (optional but recommended)

## 1. Supabase Setup

### 1.1 Create a Project

1. Create a new project at [supabase.com](https://supabase.com).
2. Note the **Project Reference** (e.g., `<project-ref>`).
3. Set a strong database password. Store it securely — you will need it for the connection URL.

### 1.2 Get the Connection URL

Use the **Transaction Pooler** for the running application:

```
postgresql://postgres.<project-ref>:<password>@aws-0-<region>.pooler.supabase.com:6543/postgres
```

The application automatically:
- Strips `?pgbouncer=true` (not valid for psycopg2)
- Rewrites the scheme to `postgresql+psycopg2://` for SQLAlchemy compatibility

For migrations that require a session-level connection (DDL operations that PgBouncer transaction mode cannot handle), use the **Session Pooler** on port 5432:

```
postgresql://postgres.<project-ref>:<password>@aws-0-<region>.pooler.supabase.com:5432/postgres
```

### 1.3 Database Migration Strategy

The application uses `Base.metadata.create_all()` on startup, which is **additive only** — it creates tables that don't exist but never drops or alters existing ones. The `_migrate()` function adds missing columns to existing tables using `ALTER TABLE ADD COLUMN`.

**Important:** `create_all()` is sufficient for initial deployment. For subsequent schema changes that require column type changes or table restructuring, run migrations manually via the Supabase SQL Editor using the session pooler connection.

**Safe migration procedure for existing data:**

1. Connect to Supabase via the Session Pooler (port 5432).
2. Run the migration SQL (the application's `_migrate()` function handles additive changes automatically on next startup).
3. Restart the application — `create_all()` + `_migrate()` will apply any remaining additive changes.

The application never drops tables or deletes data. All migrations are additive (ADD COLUMN, ALTER COLUMN TYPE for widening).

### 1.4 Audit Table RLS

The application applies RLS policies on startup via `ks/audit_worm.py`:

```sql
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_insert_only ON audit_logs AS PERMISSIVE FOR INSERT WITH CHECK (true);
CREATE POLICY audit_select_all ON audit_logs AS PERMISSIVE FOR SELECT USING (true);
-- No UPDATE/DELETE policy → denied by default under RLS
```

**Known limitation:** Supabase's default `postgres` role is a superuser and bypasses all RLS policies, including FORCE. This means UPDATE/DELETE are not blocked at the DB level when connected as `postgres`. The application-level WORM restriction (no UPDATE/DELETE routes) and HMAC chain verification (detects tampering) provide the primary protection.

To achieve full DB-level immutability, create a non-superuser application role:
1. In Supabase SQL Editor: `CREATE ROLE lume_app WITH LOGIN PASSWORD '<strong-password>';`
2. Grant permissions: `GRANT INSERT, SELECT ON ALL TABLES IN SCHEMA public TO lume_app;`
3. Use the `lume_app` connection string in `LUME_KS_DB_URL`.
4. RLS with FORCE will then block UPDATE/DELETE from the application.

## 2. Render Setup

### 2.1 Create the Service

1. Go to [render.com](https://render.com) and create a new **Web Service**.
2. Connect the team's GitHub repository (`Gaganbtech/LUME-Security`).
3. Select the branch: the team's agreed production branch (typically `main` after PR merge).
4. Set **Root Directory** to `enterprise-key-service`.
5. Render will auto-detect `render.yaml` — review the configuration.

### 2.2 render.yaml Configuration

```yaml
services:
  - type: web
    name: travlume-enterprise-key-portal
    runtime: python
    rootDir: enterprise-key-service
    buildCommand: pip install -e .
    startCommand: uvicorn ks.main:app --host 0.0.0.0 --port $PORT
    envVars:
      - key: LUME_KS_ENV
        value: production
      - key: LUME_KS_SECRET_KEY
        generateValue: true
      - key: LUME_KS_AUDIT_SECRET
        generateValue: true
      - key: LUME_KS_ENCRYPTION_KEY
        generateValue: true
      - key: LUME_KS_DB_URL
        value: <your-supabase-transaction-pooler-url>
      - key: LUME_KS_ALLOWED_ORIGINS
        value: https://your-domain.com
      - key: LUME_KS_TOKEN_EXPIRE_SECONDS
        value: "28800"
    healthCheckPath: /
```

### 2.3 Environment Variables

| Variable | Purpose | Source |
|----------|---------|--------|
| `LUME_KS_ENV` | Must be `production` | Set in render.yaml |
| `LUME_KS_SECRET_KEY` | JWT session signing | Render `generateValue: true` |
| `LUME_KS_AUDIT_SECRET` | Audit log HMAC signing | Render `generateValue: true` |
| `LUME_KS_ENCRYPTION_KEY` | Fernet encryption for pending keys | Render `generateValue: true` |
| `LUME_KS_DB_URL` | Supabase transaction pooler URL | Set manually with your password |
| `LUME_KS_ALLOWED_ORIGINS` | CORS origins (your domain) | Set to your domain |
| `LUME_KS_TOKEN_EXPIRE_SECONDS` | Session/token expiry (28800 = 8h) | Set in render.yaml |

**Never place actual secrets in `render.yaml`, source code, or documentation.** The three secret variables use `generateValue: true` so Render generates them automatically.

### 2.4 Production Behavior

When `LUME_KS_ENV=production`:
- Cookies are HTTPS-only (`secure=True`)
- `/docs` and `/openapi.json` are disabled (API structure not exposed)
- `LUME_KS_ENCRYPTION_KEY` is required — the application refuses to start without it
- CORS is restricted to `LUME_KS_ALLOWED_ORIGINS`

## 3. Initial Admin Seeding

After the first deployment, create the initial admin account:

```bash
# On the Render shell (or locally with LUME_KS_DB_URL pointing to Supabase):
python -m ks.seed --username admin --email admin@yourdomain.com --role admin --generate-password
```

The generated password is printed once. Store it securely. The seeded account is pre-approved (`is_approved=True`).

**Alternative:** Seed locally before deploying:
1. Set `LUME_KS_DB_URL` to your Supabase URL in `.env`
2. Run `python -m ks.seed --username admin --email admin@yourdomain.com --role admin --generate-password`
3. The admin account will be in the database when the application starts

## 4. Domain and CORS Configuration

1. In Cloudflare (or your DNS provider), create a CNAME record pointing to your Render service URL.
2. Set `LUME_KS_ALLOWED_ORIGINS` to your domain (e.g., `https://keys.travlume.com`).
3. If using Cloudflare WAF, ensure it allows POST requests to `/auth/login`, `/keys/validate`, `/api/keys/request`, and `/api/admin/*`.

## 5. Health Check

The health check path is `/` (the landing page). Render will verify this returns HTTP 200.

## 6. Rollback Procedure

To roll back to a previous deployment:

1. In Render, go to your service → **Deploys**.
2. Find the previous working deployment.
3. Click **Roll back to this deploy**.
4. Render will redeploy the previous commit.

If a database migration was part of the failed deploy:
1. The application only performs additive migrations (ADD COLUMN, CREATE TABLE).
2. Rolling back the application code is safe — older code ignores newer columns.
3. Never run `DROP TABLE` or `DELETE FROM` as a rollback strategy.

## 7. Post-Deployment Smoke Test

See the checklist in `PRE_PRODUCTION_TEST_REPORT.md` or run:

```bash
# 1. Landing page loads
curl -s https://your-domain.com/ | grep -q "TravLume"

# 2. Health check
curl -s -o /dev/null -w "%{http_code}" https://your-domain.com/
# Expected: 200

# 3. API docs disabled in production
curl -s -o /dev/null -w "%{http_code}" https://your-domain.com/docs
# Expected: 404

# 4. Login endpoint works
curl -s -X POST https://your-domain.com/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"<your-password>"}'
# Expected: 200 with access_token

# 5. Key validation works
curl -s -X POST https://your-domain.com/keys/validate \
  -H "Content-Type: application/json" \
  -d '{"key":"<a-valid-key>","scan_target":"https://example.com"}'
# Expected: 200 (consumed) or 401 (invalid/already consumed)
```

## 8. Security Checklist

- [ ] Supabase database password is strong and stored securely
- [ ] `LUME_KS_SECRET_KEY`, `LUME_KS_AUDIT_SECRET`, `LUME_KS_ENCRYPTION_KEY` are all different values
- [ ] `LUME_KS_ENV=production` is set
- [ ] `LUME_KS_ALLOWED_ORIGINS` is set to your domain (not localhost)
- [ ] HTTPS is enforced (Cloudflare or Render's built-in TLS)
- [ ] `/docs` and `/openapi.json` return 404 in production
- [ ] `.env` file is never committed to git
- [ ] No hardcoded credentials in source code or test scripts
- [ ] Initial admin password has been changed from the generated default
- [ ] Audit log verification endpoint (`/api/admin/audit/verify`) returns `valid: true`
