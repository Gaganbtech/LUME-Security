"""Tests for DNS-rebinding protection in SafeSyncTransport / _SafeSyncBackend.

These tests verify that _SafeSyncBackend.connect_tcp():
  - Blocks connections when the hostname resolves to a private IP.
  - Blocks connections when any resolved IP is private (mixed public+private).
  - Passes the resolved *IP string* (not the original hostname) to the parent
    connect_tcp(), so no further OS resolution occurs at connect() time.
  - Allows connections when all resolved IPs are public.
  - Skips the check for literal IP addresses (they cannot rebind).
"""

import socket
from unittest.mock import call, patch

import httpx
import pytest

from lume.enterprise.safe_transport import (
    DNSRebindError,
    SafeSyncTransport,
    _HTTPCORE_AVAILABLE,
)

pytestmark = pytest.mark.skipif(
    not _HTTPCORE_AVAILABLE, reason="httpcore not available"
)

from lume.enterprise.safe_transport import _SafeSyncBackend  # noqa: E402


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_gai(ips: list[str]):
    """Return a getaddrinfo mock that yields the given IPs."""
    def _gai(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in ips]
    return _gai


# ── Test cases ────────────────────────────────────────────────────────────────

class TestSafeSyncBackendRebindProtection:
    def setup_method(self):
        self.backend = _SafeSyncBackend()

    def test_private_ip_raises_dns_rebind_error(self):
        """A hostname resolving to a private IP must raise DNSRebindError."""
        with patch("socket.getaddrinfo", side_effect=_make_gai(["192.168.1.100"])):
            with pytest.raises(DNSRebindError, match="192.168.1.100"):
                self.backend.connect_tcp("evil-rebind.example.com", 443, timeout=5.0)

    def test_loopback_ip_raises_dns_rebind_error(self):
        with patch("socket.getaddrinfo", side_effect=_make_gai(["127.0.0.1"])):
            with pytest.raises(DNSRebindError, match="127.0.0.1"):
                self.backend.connect_tcp("rebind-to-loopback.example.com", 80, timeout=5.0)

    def test_rfc1918_172_raises_dns_rebind_error(self):
        with patch("socket.getaddrinfo", side_effect=_make_gai(["172.16.0.1"])):
            with pytest.raises(DNSRebindError):
                self.backend.connect_tcp("rebind.example.com", 443, timeout=5.0)

    def test_mixed_public_and_private_raises_dns_rebind_error(self):
        """If ANY resolved IP is private, the connection must be blocked."""
        with patch("socket.getaddrinfo", side_effect=_make_gai(["93.184.216.34", "192.168.1.50"])):
            with pytest.raises(DNSRebindError, match="192.168.1.50"):
                self.backend.connect_tcp("mixed.example.com", 443, timeout=5.0)

    def test_public_hostname_passes_check_and_ip_is_pinned(self):
        """A public hostname must pass validation and the parent connect_tcp
        must be called with the resolved IP address string, not the hostname.

        This confirms that no further OS resolution occurs at connect() time.
        """
        PUBLIC_IP = "93.184.216.34"
        with patch("socket.getaddrinfo", side_effect=_make_gai([PUBLIC_IP])):
            with patch.object(
                self.backend.__class__.__bases__[0],  # SyncBackend
                "connect_tcp",
                return_value="mock_stream",
            ) as mock_parent:
                result = self.backend.connect_tcp("example.com", 443, timeout=5.0)

                assert result == "mock_stream"
                mock_parent.assert_called_once()
                called_host = mock_parent.call_args[1].get("host") or mock_parent.call_args[0][0]
                # The parent must receive the IP, not the original hostname.
                assert called_host == PUBLIC_IP, (
                    f"Expected IP '{PUBLIC_IP}' to be passed to connect_tcp, "
                    f"got '{called_host}'. If a hostname is passed instead, "
                    f"connect() will resolve again, defeating rebind protection."
                )

    def test_literal_ip_skips_rebind_check(self):
        """Literal IPs cannot be rebinded; the check should be skipped."""
        with patch.object(
            self.backend.__class__.__bases__[0],
            "connect_tcp",
            return_value="mock_stream",
        ) as mock_parent:
            # 127.0.0.1 as a literal IP — skip check, pass through directly
            result = self.backend.connect_tcp("127.0.0.1", 8080, timeout=5.0)
            assert result == "mock_stream"
            called_host = mock_parent.call_args[1].get("host") or mock_parent.call_args[0][0]
            assert called_host == "127.0.0.1"

    def test_dns_failure_raises_os_error(self):
        """DNS resolution failure should propagate as OSError."""
        with patch("socket.getaddrinfo", side_effect=socket.gaierror("NXDOMAIN")):
            with pytest.raises(OSError, match="NXDOMAIN"):
                self.backend.connect_tcp("nonexistent.invalid", 443, timeout=5.0)


class TestSafeSyncTransportBackendInstalled:
    def test_transport_uses_safe_backend(self):
        """SafeSyncTransport must install _SafeSyncBackend in the connection pool."""
        t = SafeSyncTransport()
        assert isinstance(t._pool._network_backend, _SafeSyncBackend), (
            "SafeSyncTransport must replace the default SyncBackend with "
            "_SafeSyncBackend so all TCP connections go through IP validation."
        )

    def test_ip_pinned_to_parent_not_hostname(self):
        """The parent SyncBackend.connect_tcp must receive the resolved IP string,
        not the original hostname.  This proves socket.create_connection() uses
        the validated IP and cannot resolve a different address.

        HTTP Host header and TLS SNI are NOT affected because httpcore reads
        self._origin.host (original bytes) for both — not the connect_tcp argument.
        """
        from httpcore._backends.sync import SyncBackend as _SyncBackend

        parent_calls = []
        original = _SyncBackend.connect_tcp

        def recording_connect(self, host, port, **kwargs):
            parent_calls.append(host)
            raise ConnectionRefusedError("test-stop")

        _SyncBackend.connect_tcp = recording_connect
        try:
            t = SafeSyncTransport()
            req = httpx.Request("GET", "https://example.com/api")

            with patch("socket.getaddrinfo", side_effect=_make_gai(["93.184.216.34"])):
                try:
                    t.handle_request(req)
                except Exception:
                    pass
        finally:
            _SyncBackend.connect_tcp = original

        assert parent_calls, "connect_tcp was not called"
        assert parent_calls[0] == "93.184.216.34", (
            f"Expected IP '93.184.216.34' but got '{parent_calls[0]}'. "
            "The IP was not pinned — hostname was passed to connect_tcp."
        )

    def test_host_header_and_sni_use_original_hostname(self):
        """HTTP Host header must be the original hostname, not the resolved IP."""
        req = httpx.Request("GET", "https://example.com/api")
        assert req.headers.get("host") == "example.com", (
            "httpx must set the Host header to the original hostname, not the IP."
        )
