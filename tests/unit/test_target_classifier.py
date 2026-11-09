"""Unit tests for the enterprise target classifier."""

from unittest.mock import patch

import pytest

from lume.enterprise.target_classifier import (
    TargetClassificationError,
    classify_target,
    is_local_target,
)


# ── Private / loopback addresses ──────────────────────────────────────────────

class TestLocalTargets:
    def test_localhost_is_local(self):
        assert is_local_target("http://localhost:8000/chat") is True

    def test_loopback_ip_is_local(self):
        assert is_local_target("http://127.0.0.1:9000/v1/chat") is True

    def test_ipv6_loopback_is_local(self):
        assert is_local_target("https://[::1]:8080/path") is True

    def test_rfc1918_10_is_local(self):
        assert is_local_target("http://10.0.0.1:8080/api") is True

    def test_rfc1918_172_is_local(self):
        assert is_local_target("http://172.16.50.1:8080/api") is True

    def test_rfc1918_192_168_is_local(self):
        assert is_local_target("http://192.168.1.100:8080/api") is True

    def test_link_local_is_local(self):
        assert is_local_target("http://169.254.1.5:8080/api") is True

    def test_test_fixture_vulnerable_ai(self):
        assert is_local_target("http://vulnerable-ai:8001/v1/chat") is True

    def test_test_fixture_protected_ai(self):
        assert is_local_target("http://protected-ai:8002/v1/chat") is True

    def test_test_fixture_test_ai(self):
        assert is_local_target("http://test-ai:8003/v1/chat") is True

    def test_dotlocal_hostname_is_local(self):
        assert is_local_target("http://mydevmachine.local:5000/api") is True


# ── External addresses ────────────────────────────────────────────────────────

class TestExternalTargets:
    def test_public_hostname_resolves_to_external(self):
        # Patch DNS so the test doesn't make real network calls
        with patch(
            "lume.enterprise.target_classifier.resolve_hostname",
            return_value=["93.184.216.34"],  # example.com IP
        ):
            assert is_local_target("https://example.com/api") is False

    def test_public_ip_is_external(self):
        assert is_local_target("https://8.8.8.8/api") is False

    def test_classify_external(self):
        with patch(
            "lume.enterprise.target_classifier.resolve_hostname",
            return_value=["93.184.216.34"],
        ):
            assert classify_target("https://example.com/api") == "external"

    def test_classify_local(self):
        assert classify_target("http://localhost:8000/chat") == "local"


# ── DNS resolution failure ────────────────────────────────────────────────────

class TestDNSFailure:
    def test_dns_failure_raises_classification_error(self):
        with patch(
            "lume.enterprise.target_classifier.resolve_hostname",
            side_effect=TargetClassificationError("DNS failed"),
        ):
            with pytest.raises(TargetClassificationError):
                is_local_target("https://unresolvable.invalid/api")


# ── DNS rebinding prevention ──────────────────────────────────────────────────

class TestDNSRebindingPrevention:
    def test_hostname_resolving_to_private_ip_is_local(self):
        """A hostname that resolves to a private IP must be treated as local."""
        with patch(
            "lume.enterprise.target_classifier.resolve_hostname",
            return_value=["192.168.1.50"],
        ):
            assert is_local_target("https://rebind.example.com/api") is True

    def test_hostname_with_mixed_ips_one_public_is_external(self):
        """If ANY resolved IP is non-private, the target is external."""
        with patch(
            "lume.enterprise.target_classifier.resolve_hostname",
            return_value=["192.168.1.50", "93.184.216.34"],
        ):
            assert is_local_target("https://mixed.example.com/api") is False
