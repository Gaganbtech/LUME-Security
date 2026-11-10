"""Atomicity tests: concurrent validation requests must not both succeed."""

import threading


def _validate(client, key: str, target: str, results: list, idx: int):
    resp = client.post(
        "/keys/validate",
        json={"key": key, "scan_target": target},
    )
    results[idx] = resp.status_code


def test_concurrent_validation_only_one_succeeds(registered_user, client):
    """Two threads racing to consume the same key: exactly one must get 200."""
    _, _, token = registered_user
    key = client.post(
        "/api/keys/issue",
        headers={"Authorization": f"Bearer {token}"},
    ).json()["key"]

    results = [None, None]
    t1 = threading.Thread(target=_validate, args=(client, key, "https://a.example.com", results, 0))
    t2 = threading.Thread(target=_validate, args=(client, key, "https://b.example.com", results, 1))

    t1.start()
    t2.start()
    t1.join()
    t2.join()

    status_codes = sorted(results)  # noqa: F841 — kept for debug readability
    # Exactly one 200, exactly one 401
    assert 200 in results, f"Expected one success, got: {results}"
    assert 401 in results, f"Expected one rejection, got: {results}"
    # Not both 200
    assert results.count(200) == 1, f"Key consumed twice: {results}"


def test_scan_failure_does_not_restore_key(registered_user, client):
    """After a key is consumed, a simulated scan failure does not make it reusable.

    This is a design property: the key service has no 'unconsume' endpoint.
    Attempting to re-validate the same key after it was consumed must still fail.
    """
    _, _, token = registered_user
    key = client.post(
        "/api/keys/issue",
        headers={"Authorization": f"Bearer {token}"},
    ).json()["key"]

    # Consume the key
    consume_resp = client.post(
        "/keys/validate",
        json={"key": key, "scan_target": "https://target.example.com"},
    )
    assert consume_resp.status_code == 200

    # Simulate scan failure by trying to consume again (there is no restore endpoint)
    retry_resp = client.post(
        "/keys/validate",
        json={"key": key, "scan_target": "https://target.example.com"},
    )
    assert retry_resp.status_code == 401
    assert retry_resp.json()["detail"]["reason"] == "already_consumed"
