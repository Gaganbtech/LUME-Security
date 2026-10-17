"""Unit tests for Target Adapters and Target Manager."""

import pytest

from lume.adapters.local.mock import LocalMockAdapter
from lume.core.target_manager.manager import (
    TargetAuthorizationError,
    TargetManager,
    TargetValidationError,
)


def test_target_manager_url_validation():
    # Valid URLs
    assert TargetManager.validate_target_url("http://localhost:8000") == "http://localhost:8000"
    assert TargetManager.validate_target_url("https://api.example.com/v1") == "https://api.example.com/v1"

    # Missing scheme
    with pytest.raises(TargetValidationError):
        TargetManager.validate_target_url("localhost:8000")

    # Unsupported scheme
    with pytest.raises(TargetValidationError):
        TargetManager.validate_target_url("ftp://localhost:8000")

    # Empty URL
    with pytest.raises(TargetValidationError):
        TargetManager.validate_target_url("")


def test_target_manager_authorization():
    # Localhost is auto-authorized
    assert TargetManager.verify_authorization("http://localhost:8000") is True
    assert TargetManager.verify_authorization("http://127.0.0.1:8080") is True

    # External targets require explicit confirmation
    with pytest.raises(TargetAuthorizationError):
        TargetManager.verify_authorization("https://external-target.com", authorized=False)

    assert TargetManager.verify_authorization("https://external-target.com", authorized=True) is True


def test_local_mock_adapter():
    adapter = LocalMockAdapter(response_handler=lambda p: f"Echo: {p}")
    assert adapter.adapter_type == "local"
    assert adapter.health_check() is True

    resp = adapter.send_prompt("Hello LUME")
    assert resp.raw_text == "Echo: Hello LUME"
    assert resp.status_code == 200


def test_http_adapter_payload_and_headers():
    from lume.adapters.base import TargetConfig
    from lume.adapters.http.client import HTTPTargetAdapter

    config = TargetConfig(
        endpoint="https://api.openai-client.com/v1/chat/completions",
        headers={"Authorization": "Bearer test-key-123", "X-Client-Org": "Org-42"},
        model_name="gpt-4o",
        extra_params={"payload_format": "openai"},
    )
    adapter = HTTPTargetAdapter(config)
    assert adapter.default_headers["Authorization"] == "Bearer test-key-123"
    assert adapter.default_headers["X-Client-Org"] == "Org-42"

    body = adapter._build_request_body("test injection prompt")
    assert body["model"] == "gpt-4o"
    assert "messages" in body
    assert body["messages"][0]["role"] == "user"
    assert body["messages"][0]["content"] == "test injection prompt"
