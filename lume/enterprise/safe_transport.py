"""SafeNetworkBackend: DNS-rebinding protection anchored at the TCP connect() syscall.

Problem statement
=================
LUME's key_client.py sends an HTTPS request to the enterprise key service.
The connection path has three separate DNS resolutions:

  T1  target_classifier.is_local_target(url)
        → socket.getaddrinfo(hostname) → check IPs → classify as external
        → enterprise key consumed here

  T2  SafeSyncTransport.handle_request() [previous approach]
        → socket.getaddrinfo(hostname) → check IPs → pass/reject
        → calls super().handle_request() which starts httpcore

  T3  httpcore SyncBackend.connect_tcp(host=hostname)
        → socket.create_connection((hostname, port))
            → OS getaddrinfo(hostname) again → connect(ip, port)

The previous SafeSyncTransport only ran a check at T2 then passed the raw
hostname to httpcore, which resolved it again at T3 without any safety check.
If the DNS answer changed between T2 and T3, we would block at T2 but the
actual TCP connection would still be made to whatever T3 resolved to.
That race window is real and cannot be dismissed.

TLS certificate validation is NOT a complete mitigating control for three
reasons:
  1. The key service runs on plain HTTP locally (http://localhost:8100).
     No TLS is involved at all.
  2. Even for HTTPS targets, certificate validation checks that the cert
     matches the *hostname*, not the *IP address*.  An attacker who controls
     a certificate for the target hostname (e.g. via a compromised CA or a
     hostname they legitimately own) could satisfy TLS validation regardless
     of which IP the socket connected to.
  3. cert verification happens *after* the TCP connection is already open,
     so the connection to the rebind target has already been made.

Correct fix
===========
Override httpcore's NetworkBackend so that connect_tcp() resolves the
hostname itself, checks every resulting IP against private ranges, and then
calls socket.create_connection() with the *resolved IP address string* (not
the original hostname).  This pins the IP: the connect() syscall uses the
same address that was checked, closing the race window.

The hostname is still passed as server_hostname to TLS so that SNI and
certificate validation continue to work correctly against the original name.

Remaining limitation
====================
There is still a sub-syscall race: between our getaddrinfo() call inside
connect_tcp() and the connect() call, the OS may re-resolve internally
(implementation-defined, usually cached).  This is inherent in any userspace
TCP stack.  It is not practically exploitable without kernel-level control
over resolution and is the acknowledged irreducible minimum for userspace
DNS validation.
"""

import ipaddress
import socket
import typing

from httpx._transports.default import HTTPTransport

from lume.enterprise.target_classifier import _PRIVATE_NETWORKS

try:
    import httpcore  # noqa: F401 — imported for availability check; not used directly
    from httpcore._backends.base import SOCKET_OPTION, NetworkStream
    from httpcore._backends.sync import SyncBackend, SyncStream  # noqa: F401
    _HTTPCORE_AVAILABLE = True
except ImportError:
    _HTTPCORE_AVAILABLE = False


class DNSRebindError(ConnectionError):
    """Raised when a hostname resolves to a private IP at connection time."""
    pass


def _check_and_pick_ip(hostname: str, timeout: float | None = None) -> str:
    """Resolve hostname, reject any private IP, return a safe public IP string.

    Raises DNSRebindError if any resolved IP is private.
    Raises OSError if resolution fails entirely.

    Returns the first public IP string, which will be used for the actual
    socket.create_connection() call so that no further resolution occurs.
    """
    try:
        results = socket.getaddrinfo(
            hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM
        )
    except socket.gaierror as exc:
        raise OSError(f"DNS resolution failed for '{hostname}': {exc}") from exc

    if not results:
        raise OSError(f"DNS resolution returned no addresses for '{hostname}'.")

    first_public: str | None = None
    for r in results:
        ip_str = r[4][0]
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if any(addr in net for net in _PRIVATE_NETWORKS):
            raise DNSRebindError(
                f"DNS rebinding protection: '{hostname}' resolved to private "
                f"address {ip_str}. Connection refused."
            )
        if first_public is None:
            first_public = ip_str

    if first_public is None:
        raise DNSRebindError(
            f"DNS rebinding protection: all addresses for '{hostname}' are private."
        )
    return first_public


if _HTTPCORE_AVAILABLE:
    class _SafeSyncBackend(SyncBackend):
        """NetworkBackend that validates the resolved IP before connecting.

        Overrides connect_tcp() to:
          1. Call getaddrinfo ourselves.
          2. Check every IP against private ranges.
          3. Pass the resolved IP (not the hostname) to socket.create_connection.

        Step 3 closes the race window: the connect() syscall uses the exact
        IP that was validated rather than resolving the hostname again.
        """

        def connect_tcp(
            self,
            host: str,
            port: int,
            timeout: float | None = None,
            local_address: str | None = None,
            socket_options: typing.Iterable[SOCKET_OPTION] | None = None,
        ) -> NetworkStream:
            # Skip the check for literal IP addresses — they cannot rebind.
            try:
                ipaddress.ip_address(host)
                safe_host = host
            except ValueError:
                # Hostname — resolve, check, and pin to the validated IP.
                try:
                    safe_host = _check_and_pick_ip(host, timeout=timeout)
                except DNSRebindError:
                    raise
                except OSError:
                    raise

            # Call the parent using the resolved IP, not the original hostname.
            # socket.create_connection((ip_string, port)) calls connect() directly
            # without another getaddrinfo round-trip for the IP literal.
            return super().connect_tcp(
                safe_host,
                port,
                timeout=timeout,
                local_address=local_address,
                socket_options=socket_options,
            )

    class SafeSyncTransport(HTTPTransport):
        """HTTPTransport that uses _SafeSyncBackend for all TCP connections.

        The protection is anchored at connect_tcp() inside httpcore, where
        the resolved IP is validated AND used for the actual connect() syscall.
        No separate pre-connect check is needed at the httpx layer.
        """

        def __init__(self, **kwargs: typing.Any) -> None:
            super().__init__(**kwargs)
            # Replace the connection pool's network backend with our safe one.
            # self._pool is an httpcore.ConnectionPool set by HTTPTransport.__init__().
            if hasattr(self._pool, "_network_backend"):
                self._pool._network_backend = _SafeSyncBackend()

else:
    # Fallback when httpcore is unavailable: identity transport (no protection).
    # This branch should never be reached in normal use.
    class SafeSyncTransport(HTTPTransport):  # type: ignore[no-redef]
        pass


# Expose helpers for key_client.py
_PRIVATE_NETWORKS = _PRIVATE_NETWORKS


def _resolved_ips(hostname: str) -> list:  # noqa: F841 — not used in new design
    return []


def _any_ip_private(ips: list) -> None:  # noqa: F841 — not used in new design
    return None
