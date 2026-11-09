"""Unit tests for the enterprise key authorization system.

All tests mock the key service and DNS resolution — no real network calls.
"""

from unittest.mock import MagicMock, patch

import pytest

from lume.core.target_manager.manager import (
    TargetAuthorizationError,
    TargetManager,
    TargetValidationError,
)
from lume.enterprise.key_client import KeyConsumedReceipt, KeyValidationError


# ── Helpers ───────────────────────────────────────────────────────────────────

def _local_adapter():
    """Mock that makes is_local_target return True."""
    return patch(
        "lume.core.target_manager.manager.is_local_target",
        return_value=True,
    )


def _external_adapter():
    """Mock that makes is_local_target return False (external target)."""
    return patch(
        "lume.core.target_manager.manager.is_local_target",
        return_value=False,
    )


def _good_key():
    """Mock that makes key validation succeed."""
    from datetime import datetime, timezone
    return patch(
        "lume.core.target_manager.manager.validate_enterprise_key",
        return_value=KeyConsumedReceipt(
            consumed_at=datetime.now(timezone.utc),
            message="Key accepted.",
        ),
    )


def _bad_key(reason: str = "not_found"):
    """Mock that makes key validation fail with given reason."""
    return patch(
        "lume.core.target_manager.manager.validate_enterprise_key",
        side_effect=KeyValidationError("Key rejected.", reason=reason),
    )


def _service_down():
    """Mock that simulates key service being unreachable."""
    return patch(
        "lume.core.target_manager.manager.validate_enterprise_key",
        side_effect=KeyValidationError("Service unreachable.", reason="service_unavailable"),
    )


# ── Local targets: no enterprise key required ─────────────────────────────────

class TestLocalTargetNoKeyRequired:
    def test_local_target_no_key_no_authorized_accepted(self):
        with _local_adapter():
            config = TargetManager.create_target_config(
                endpoint="http://localhost:8000/v1/chat",
                authorized=False,
            )
        assert config.endpoint == "http://localhost:8000/v1/chat"

    def test_local_target_with_key_still_accepted(self):
        """Enterprise key is silently ignored for local targets."""
        with _local_adapter():
            config = TargetManager.create_target_config(
                endpoint="http://localhost:8000/v1/chat",
                authorized=False,
                enterprise_key="some-key-value",
            )
        assert config.endpoint == "http://localhost:8000/v1/chat"

    def test_local_schemeless_no_key_accepted(self):
        with _local_adapter():
            config = TargetManager.create_target_config(
                endpoint="localhost:8000/v1/chat",
                authorized=False,
            )
        assert config.endpoint == "https://localhost:8000/v1/chat"

    def test_test_fixture_hostnames_no_key_required(self):
        for hostname in ("vulnerable-ai", "protected-ai", "test-ai"):
            with _local_adapter():
                config = TargetManager.create_target_config(
                    endpoint=f"http://{hostname}:8080/v1/chat",
                    authorized=False,
                )
            assert hostname in config.endpoint


# ── External targets: both --authorized AND enterprise key required ────────────

class TestExternalTargetRequiresBothChecks:
    def test_external_without_authorized_flag_blocked(self):
        with _external_adapter():
            with pytest.raises(TargetAuthorizationError) as exc_info:
                TargetManager.create_target_config(
                    endpoint="https://external-ai.example.com/v1/chat",
                    authorized=False,
                    enterprise_key="valid-key",
                )
        assert "--authorized" in str(exc_info.value)

    def test_external_without_key_blocked(self):
        with _external_adapter(), _good_key():
            with pytest.raises(TargetAuthorizationError) as exc_info:
                TargetManager.create_target_config(
                    endpoint="https://external-ai.example.com/v1/chat",
                    authorized=True,
                    enterprise_key=None,
                )
        assert "Enterprise Key" in str(exc_info.value)

    def test_external_empty_key_blocked(self):
        with _external_adapter():
            with pytest.raises(TargetAuthorizationError):
                TargetManager.create_target_config(
                    endpoint="https://external-ai.example.com/v1/chat",
                    authorized=True,
                    enterprise_key="   ",
                )

    def test_external_with_valid_key_and_authorized_accepted(self):
        with _external_adapter(), _good_key():
            config = TargetManager.create_target_config(
                endpoint="https://external-ai.example.com/v1/chat",
                authorized=True,
                enterprise_key="valid-enterprise-key-abc123",
            )
        assert config.endpoint == "https://external-ai.example.com/v1/chat"

    def test_external_already_consumed_key_blocked(self):
        with _external_adapter(), _bad_key(reason="already_consumed"):
            with pytest.raises(TargetAuthorizationError) as exc_info:
                TargetManager.create_target_config(
                    endpoint="https://external-ai.example.com/v1/chat",
                    authorized=True,
                    enterprise_key="already-used-key",
                )
        # Error must not contain the plaintext key
        assert "already-used-key" not in str(exc_info.value)

    def test_external_not_found_key_blocked(self):
        with _external_adapter(), _bad_key(reason="not_found"):
            with pytest.raises(TargetAuthorizationError):
                TargetManager.create_target_config(
                    endpoint="https://external-ai.example.com/v1/chat",
                    authorized=True,
                    enterprise_key="nonexistent-key",
                )

    def test_service_unavailable_blocks_external_scan(self):
        """Fail-closed: key service down must block external scans."""
        with _external_adapter(), _service_down():
            with pytest.raises(TargetAuthorizationError) as exc_info:
                TargetManager.create_target_config(
                    endpoint="https://external-ai.example.com/v1/chat",
                    authorized=True,
                    enterprise_key="valid-key",
                )
        assert "service" in str(exc_info.value).lower() or "unavailable" in str(exc_info.value).lower()

    def test_key_not_echoed_in_authorization_error(self):
        """Plaintext key must never appear in exception messages."""
        secret_key = "SuperSecretEnterpriseKey_abc123"
        with _external_adapter(), _bad_key(reason="already_consumed"):
            with pytest.raises(TargetAuthorizationError) as exc_info:
                TargetManager.create_target_config(
                    endpoint="https://external-ai.example.com/v1/chat",
                    authorized=True,
                    enterprise_key=secret_key,
                )
        assert secret_key not in str(exc_info.value)


# ── Key consumption is one-shot ───────────────────────────────────────────────

class TestKeyConsumptionOneShot:
    def test_key_consumed_exactly_once_per_call(self):
        """validate_enterprise_key is called exactly once per create_target_config."""
        with _external_adapter():
            with patch(
                "lume.core.target_manager.manager.validate_enterprise_key",
            ) as mock_validate:
                from datetime import datetime, timezone
                mock_validate.return_value = KeyConsumedReceipt(
                    consumed_at=datetime.now(timezone.utc),
                    message="Key accepted.",
                )
                TargetManager.create_target_config(
                    endpoint="https://external-ai.example.com/v1/chat",
                    authorized=True,
                    enterprise_key="one-time-key",
                )
            mock_validate.assert_called_once()
            _, kwargs = mock_validate.call_args
            # Key must be passed; target must be passed
            assert kwargs.get("plaintext_key") or mock_validate.call_args[0]

    def test_post_consumption_second_call_fails(self):
        """Once consumed, the same key cannot be used again."""
        call_count = {"n": 0}

        def side_effect(**kwargs):
            call_count["n"] += 1
            if call_count["n"] > 1:
                raise KeyValidationError("Already consumed.", reason="already_consumed")
            from datetime import datetime, timezone
            return KeyConsumedReceipt(consumed_at=datetime.now(timezone.utc), message="OK")

        with _external_adapter():
            with patch(
                "lume.core.target_manager.manager.validate_enterprise_key",
                side_effect=side_effect,
            ):
                # First call succeeds
                TargetManager.create_target_config(
                    endpoint="https://external-ai.example.com/v1/chat",
                    authorized=True,
                    enterprise_key="reused-key",
                )
                # Second call with same key must fail
                with pytest.raises(TargetAuthorizationError):
                    TargetManager.create_target_config(
                        endpoint="https://external-ai.example.com/v1/chat",
                        authorized=True,
                        enterprise_key="reused-key",
                    )


# ── Existing URL validation must be unchanged ─────────────────────────────────

class TestUrlValidationUnchanged:
    def test_invalid_url_still_rejected(self):
        with pytest.raises(TargetValidationError):
            TargetManager.create_target_config(endpoint="ftp://example.com")

    def test_empty_url_still_rejected(self):
        with pytest.raises(TargetValidationError):
            TargetManager.create_target_config(endpoint="")

    def test_malformed_scheme_still_rejected(self):
        with pytest.raises(TargetValidationError):
            TargetManager.create_target_config(endpoint="http:example.com")

    def test_empty_port_still_rejected(self):
        with pytest.raises(TargetValidationError):
            TargetManager.create_target_config(endpoint="https://example.com:")
