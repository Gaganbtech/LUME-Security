"""Tests for key issuance, listing, and validation."""


def test_issue_key_authenticated(registered_user, client):
    _, _, token = registered_user
    resp = client.post(
        "/api/keys/issue",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert "key" in data
    assert "key_id" in data
    assert "created_at" in data
    # Key must be non-trivially long (43 chars for token_urlsafe(32))
    assert len(data["key"]) >= 40


def test_issue_key_unauthenticated(client):
    resp = client.post("/api/keys/issue")
    assert resp.status_code == 401


def test_issued_key_not_in_list(registered_user, client):
    """Metadata is returned but plaintext key must not appear in /api/keys/me."""
    _, _, token = registered_user
    issue_resp = client.post(
        "/api/keys/issue",
        headers={"Authorization": f"Bearer {token}"},
    )
    issued_key = issue_resp.json()["key"]

    list_resp = client.get(
        "/api/keys/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert list_resp.status_code == 200
    # Plaintext key must NOT appear anywhere in the listing response
    assert issued_key not in list_resp.text


def test_validate_key_consumed_once(registered_user, client):
    """A valid key is accepted the first time and rejected the second time."""
    _, _, token = registered_user
    key = client.post(
        "/api/keys/issue",
        headers={"Authorization": f"Bearer {token}"},
    ).json()["key"]

    # First validation — must succeed
    resp1 = client.post(
        "/keys/validate",
        json={"key": key, "scan_target": "https://external-ai.example.com/v1/chat"},
    )
    assert resp1.status_code == 200
    assert resp1.json()["status"] == "consumed"

    # Second validation with same key — must be rejected
    resp2 = client.post(
        "/keys/validate",
        json={"key": key, "scan_target": "https://external-ai.example.com/v1/chat"},
    )
    assert resp2.status_code == 401
    detail = resp2.json()["detail"]
    assert detail["reason"] == "already_consumed"
    # Plaintext key must not appear in the error response
    assert key not in resp2.text


def test_validate_nonexistent_key(client):
    resp = client.post(
        "/keys/validate",
        json={"key": "NONEXISTENT_KEY_THAT_DOES_NOT_EXIST_abc", "scan_target": "https://example.com"},
    )
    assert resp.status_code == 401
    assert resp.json()["detail"]["reason"] == "not_found"


def test_validate_malformed_key(client):
    resp = client.post("/keys/validate", json={"key": "x", "scan_target": "https://example.com"})
    assert resp.status_code in (400, 422)


def test_validate_missing_scan_target(client):
    resp = client.post("/keys/validate", json={"key": "somekey"})
    assert resp.status_code == 422


def test_key_not_in_validation_error_response(registered_user, client):
    """Plaintext key must never appear in a rejection response body."""
    _, _, token = registered_user
    key = client.post(
        "/api/keys/issue",
        headers={"Authorization": f"Bearer {token}"},
    ).json()["key"]

    # Consume the key
    client.post(
        "/keys/validate",
        json={"key": key, "scan_target": "https://example.com"},
    )

    # Try to consume again; key must not appear in the response
    resp = client.post(
        "/keys/validate",
        json={"key": key, "scan_target": "https://example.com"},
    )
    assert key not in resp.text


def test_list_keys_shows_consumed_status(registered_user, client):
    _, _, token = registered_user
    key = client.post(
        "/api/keys/issue",
        headers={"Authorization": f"Bearer {token}"},
    ).json()["key"]

    # Before consumption
    list_before = client.get(
        "/api/keys/me",
        headers={"Authorization": f"Bearer {token}"},
    ).json()
    assert list_before["keys"][0]["is_consumed"] is False
    assert list_before["keys"][0]["consumed_at"] is None

    # Consume
    client.post(
        "/keys/validate",
        json={"key": key, "scan_target": "https://external.example.com/scan"},
    )

    # After consumption
    list_after = client.get(
        "/api/keys/me",
        headers={"Authorization": f"Bearer {token}"},
    ).json()
    assert list_after["keys"][0]["is_consumed"] is True
    assert list_after["keys"][0]["consumed_at"] is not None
    # Plaintext key never in metadata
    assert key not in list_after["keys"][0].values()
