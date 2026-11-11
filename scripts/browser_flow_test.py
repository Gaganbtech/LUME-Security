"""Browser-flow simulation test: login, key issuance, one-time display verification.

Run with the key service running on http://localhost:8100:
    python scripts/browser_flow_test.py

This test:
  1. Creates a fresh test account via the seed CLI (random password, never reused).
  2. Logs in via the browser form flow (cookies, not JSON API).
  3. Issues a key and verifies it appears in the response.
  4. Reloads the dashboard and verifies the key is GONE (shown once only).
  5. Logs out and verifies the session is cleared.

The test is self-contained and repeatable: each run creates a new user
with a unique name so prior runs don't interfere.
"""

import os
import re
import subprocess
import sys
import time

import httpx

BASE = "http://localhost:8100"
SVC_DIR = os.path.dirname(os.path.dirname(__file__)) + "/enterprise-key-service"
PY = os.path.join(SVC_DIR, ".venv/Scripts/python.exe")

PASS = []
FAIL = []


def chk(label, condition, detail=""):
    tag = "PASS" if condition else "FAIL"
    entry = f"{tag}  {label}"
    if detail:
        entry += f"  [{detail}]"
    (PASS if condition else FAIL).append(entry)


def follow_with_cookie(client, resp):
    """Follow a redirect, carrying cookies manually (SameSite=strict workaround)."""
    loc = resp.headers.get("location", "/")
    cookies = {ck.name: ck.value for ck in client.cookies.jar}
    return client.get(loc, cookies=cookies)


# ── Create a fresh test account ──────────────────────────────────────────────
username = f"flowtest_{int(time.time())}"
seed_cmd = [PY, "-m", "ks.seed", "--username", username, "--email", f"{username}@local.dev",
            "--generate-password"]
seed_result = subprocess.run(seed_cmd, capture_output=True, text=True, cwd=SVC_DIR)
password = ""
for line in (seed_result.stdout + seed_result.stderr).splitlines():
    if "Generated password" in line:
        password = line.split(": ", 1)[1].strip()
        break

if not password:
    print(f"FAIL  Cannot create test account. Seed output:\n{seed_result.stdout}\n{seed_result.stderr}")
    sys.exit(1)

chk("0. Test account created", "[OK]" in (seed_result.stdout + seed_result.stderr),
    f"user={username}")

# ── Run the browser flow ──────────────────────────────────────────────────────
c = httpx.Client(base_url=BASE, follow_redirects=False)

# Step 1: Login page
r = c.get("/login")
chk("1. GET /login returns 200", r.status_code == 200)
chk("1. Login page has LUME branding", "LUME Key Service" in r.text)
chk("1. Login page has form", "<form" in r.text)
chk('1. Login page has username field', 'name="username"' in r.text)
chk('1. Login page has password field', 'type="password"' in r.text)

# Step 2: Wrong password
r_bad = c.post("/login", data={"username": username, "password": "wrong!pass99"})
chk("2. Wrong password returns 401", r_bad.status_code == 401)
chk("2. Error message shown", "Invalid username or password" in r_bad.text)

# Step 3: Correct login
r_login = c.post("/login", data={"username": username, "password": password})
chk("3. Correct login returns 303", r_login.status_code == 303)
chk("3. Redirect to /dashboard", r_login.headers.get("location") == "/dashboard")
chk("3. Set-Cookie has access_token", "access_token" in r_login.headers.get("set-cookie", ""))

# Step 4: Dashboard with cookie
r_dash = follow_with_cookie(c, r_login)
chk("4. GET /dashboard returns 200", r_dash.status_code == 200)
chk(f"4. Dashboard shows welcome for {username}", f"Welcome, {username}" in r_dash.text)
chk("4. Dashboard has Request Key button", "Request New Enterprise Key" in r_dash.text)

# Step 5: Issue key — appears once
cookies = {ck.name: ck.value for ck in c.cookies.jar}
r_issue_redir = c.post("/keys/issue", cookies=cookies)
chk("5. POST /keys/issue returns 303", r_issue_redir.status_code == 303)

r_issue = follow_with_cookie(c, r_issue_redir)
chk("5. Dashboard loads after issue", r_issue.status_code == 200)
chk("5. One-time key notice present", "Your new Enterprise Key" in r_issue.text)

key_match = re.search(r"<code>([A-Za-z0-9_-]{40,})</code>", r_issue.text)
issued_key = key_match.group(1) if key_match else None
chk("5. Key present in HTML", issued_key is not None, f"length={len(issued_key) if issued_key else 0}")
if issued_key:
    chk("5. Key is 43 chars", len(issued_key) == 43, f"actual={len(issued_key)}")

# Step 6: Reload dashboard — key must be ABSENT
cookies = {ck.name: ck.value for ck in c.cookies.jar}
r_dash2 = c.get("/dashboard", cookies=cookies)
chk("6. Second dashboard load returns 200", r_dash2.status_code == 200)
if issued_key:
    chk("6. KEY ABSENT on second load", issued_key not in r_dash2.text,
        "KEY LEAKED" if issued_key in r_dash2.text else "ok")
    chk("6. One-time notice absent", "Your new Enterprise Key" not in r_dash2.text)
chk("6. Keys table shows Available", "Available" in r_dash2.text)

# Step 7: Logout
r_logout = c.get("/logout", cookies=cookies)
chk("7. Logout returns 303", r_logout.status_code == 303)
chk("7. Logout redirects to /login", r_logout.headers.get("location") == "/login")

# Step 8: Dashboard after logout
r_after = c.get("/dashboard")
chk("8. /dashboard after logout returns 401", r_after.status_code == 401)

# ── Results ───────────────────────────────────────────────────────────────────
print()
print("=== BROWSER FLOW RESULTS ===")
for line in PASS:
    print(" ", line)
for line in FAIL:
    print(" ", line)
print()
print(f"  {len(PASS)} passed  /  {len(FAIL)} failed")
sys.exit(0 if not FAIL else 1)
