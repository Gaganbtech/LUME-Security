"""Tests for authentication endpoints."""


def test_login_success(registered_user, client):
    username, password, _ = registered_user
    resp = client.post("/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["expires_in"] > 0


def test_login_wrong_password(registered_user, client):
    username, _, _ = registered_user
    resp = client.post("/auth/login", json={"username": username, "password": "wrongpassword!"})
    assert resp.status_code == 401
    assert "detail" in resp.json()
    # Ensure plaintext password not echoed back
    assert "wrongpassword" not in resp.text


def test_login_unknown_user(client):
    resp = client.post("/auth/login", json={"username": "nobody", "password": "doesntmatter"})
    assert resp.status_code == 401


def test_login_missing_fields(client):
    resp = client.post("/auth/login", json={"username": "x"})
    assert resp.status_code == 422


def test_dashboard_redirects_unauthenticated(client):
    resp = client.get("/dashboard", follow_redirects=False)
    # Must redirect to login, not serve the page
    assert resp.status_code in (302, 303, 307, 401)
