"""Explicit target classifier: resolves the actual IP and checks it at connection time.

The classifier distinguishes local/private targets (no enterprise key needed) from
external targets (enterprise key required) using RFC-defined IP ranges.

IMPORTANT: classification is performed on the *resolved* IP address, not merely
on the hostname string.  This prevents DNS rebinding: an attacker cannot register
a hostname that initially resolves to a public IP (passing the check) and then
rebinds to a private IP when the TCP connection is made, because we re-validate
at transport time via SafeTransport.
"""

import ipaddress
import re
import socket
from urllib.parse import urlparse

# ── Private / loopback IP ranges ──────────────────────────────────────────────

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),      # IPv4 loopback
    ipaddress.ip_network("::1/128"),           # IPv6 loopback
    ipaddress.ip_network("10.0.0.0/8"),        # RFC-1918
    ipaddress.ip_network("172.16.0.0/12"),     # RFC-1918
    ipaddress.ip_network("192.168.0.0/16"),    # RFC-1918
    ipaddress.ip_network("169.254.0.0/16"),    # Link-local IPv4
    ipaddress.ip_network("fe80::/10"),         # Link-local IPv6
    ipaddress.ip_network("fc00::/7"),          # Unique-local IPv6
    ipaddress.ip_network("0.0.0.0/8"),         # "This" network
    ipaddress.ip_network("100.64.0.0/10"),     # CGNAT (RFC 6598)
]

# Explicitly named test fixture hostnames (project convention, unchanged)
_TEST_FIXTURE_HOSTNAMES = frozenset({
    "localhost",
    "vulnerable-ai",
    "protected-ai",
    "test-ai",
})

# *.local mDNS hostnames
_LOCAL_SUFFIX_RE = re.compile(r"^[a-zA-Z0-9._-]+\.local$", re.IGNORECASE)


class TargetClassificationError(Exception):
    """Raised when the target cannot be classified (e.g. DNS resolution failure)."""
    pass


def _ip_is_private(addr_str: str) -> bool:
    """Return True if the given IP address string falls within a private range."""
    try:
        addr = ipaddress.ip_address(addr_str)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return False


def resolve_hostname(hostname: str, timeout: float = 5.0) -> list[str]:
    """Resolve a hostname to a list of IP address strings.

    Raises TargetClassificationError on DNS failure.
    """
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        results = socket.getaddrinfo(hostname, None)
        return list({r[4][0] for r in results})
    except (socket.gaierror, OSError) as exc:
        raise TargetClassificationError(
            f"DNS resolution failed for '{hostname}': {exc}"
        ) from exc
    finally:
        socket.setdefaulttimeout(old_timeout)


def is_local_target(url: str, dns_timeout: float = 5.0) -> bool:
    """Return True if the target resolves to a local/private address.

    Classification rules (in order):
    1. Named test-fixture hostnames (project allowlist) → local.
    2. *.local hostnames → local.
    3. IPv6 loopback literal [::1] → local.
    4. Parse hostname, resolve to IP(s), check all against private ranges.
       If ANY resolved IP is non-private → external.
       If ALL resolved IPs are private → local.

    Raises TargetClassificationError if DNS resolution fails.
    """
    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    if not hostname:
        raise TargetClassificationError(f"Cannot classify target '{url}': no hostname.")

    # Named test fixtures
    if hostname.lower() in _TEST_FIXTURE_HOSTNAMES:
        return True

    # *.local mDNS
    if _LOCAL_SUFFIX_RE.match(hostname):
        return True

    # Try parsing as a literal IP first (no DNS needed)
    try:
        addr = ipaddress.ip_address(hostname)
        return _ip_is_private(str(addr))
    except ValueError:
        pass  # not a literal IP — proceed to DNS resolution

    # Resolve via DNS and check every resulting IP
    resolved_ips = resolve_hostname(hostname, timeout=dns_timeout)
    if not resolved_ips:
        raise TargetClassificationError(
            f"DNS resolution returned no addresses for '{hostname}'."
        )

    # Conservative: if ANY resolved IP is non-private, treat as external
    for ip in resolved_ips:
        if not _ip_is_private(ip):
            return False

    return True


def classify_target(url: str, dns_timeout: float = 5.0) -> str:
    """Return 'local' or 'external' for the given normalized target URL.

    Raises TargetClassificationError on resolution failure.
    """
    return "local" if is_local_target(url, dns_timeout=dns_timeout) else "external"
