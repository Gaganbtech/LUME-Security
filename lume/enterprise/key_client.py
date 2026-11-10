"""HTTPS client for the LUME Enterprise Key Service.

The CLI calls this module to atomically consume an enterprise key before
allowing an external scan to proceed.

Fail-closed policy: any error (connection failure, timeout, 5xx, unexpected
response) BLOCKS the scan rather than allowing it.

The plaintext key is sent over HTTPS and is never written to logs, history,
or error messages.
"""

import os
from dataclasses import dataclass
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse

import httpx

from lume.enterprise.safe_transport import SafeSyncTransport

# Hostnames that are explicitly local — the key service is intentionally
# running there and SafeSyncTransport must not block it.
_LOCAL_KS_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "0.0.0.0"})


class KeyValidationError(Exception):
    """Raised when key validation fails or the service is unreachable."""

    def __init__(self, message: str, reason: Optional[str] = None):
        super().__init__(message)
        self.reason = reason


@dataclass
class KeyConsumedReceipt:
    """Returned on successful atomic key consumption."""
    consumed_at: datetime
    message: str


def _get_service_url() -> str:
    url = os.environ.get("LUME_KEY_SERVICE_URL", "").strip().rstrip("/")
    if not url:
        raise KeyValidationError(
            "LUME_KEY_SERVICE_URL is not configured. "
            "Set it in your .env file or environment to point to the enterprise key service."
        )
    return url


def _build_transport(service_url: str) -> httpx.HTTPTransport:
    """Return the correct transport for the key service URL.

    - Local service (localhost / 127.x / ::1): plain HTTPTransport.
      SafeSyncTransport would correctly identify these as private IPs and
      block the connection — but for an explicitly configured local dev
      service that IS the intended destination.
    - Remote service: SafeSyncTransport, which pins the resolved IP to
      close the DNS-rebinding race window at connect() time.
    """
    host = (urlparse(service_url).hostname or "").lower()
    if host in _LOCAL_KS_HOSTS:
        return httpx.HTTPTransport()
    return SafeSyncTransport()


def validate_enterprise_key(
    plaintext_key: str,
    scan_target: str,
    timeout: float = 10.0,
) -> KeyConsumedReceipt:
    """Consume an enterprise key atomically against the key service.

    Args:
        plaintext_key: The enterprise key supplied by the user.
        scan_target:   The normalized target URL (stored for audit only).
        timeout:       HTTP request timeout in seconds.

    Returns:
        KeyConsumedReceipt on success.

    Raises:
        KeyValidationError on any failure — scan must not proceed.
    """
    service_url = _get_service_url()
    endpoint = f"{service_url}/keys/validate"
    transport = _build_transport(service_url)

    payload = {
        "key": plaintext_key,
        "scan_target": scan_target,
    }

    try:
        with httpx.Client(transport=transport, timeout=timeout) as client:
            resp = client.post(endpoint, json=payload)
    except httpx.TimeoutException:
        raise KeyValidationError(
            "Enterprise key service timed out. Cannot authorize external scan. "
            "Check that the key service is running at LUME_KEY_SERVICE_URL.",
            reason="service_unavailable",
        )
    except httpx.ConnectError as exc:
        raise KeyValidationError(
            f"Cannot connect to the enterprise key service: {exc}. "
            "Ensure the service is running and LUME_KEY_SERVICE_URL is correct.",
            reason="service_unavailable",
        )
    except Exception as exc:
        raise KeyValidationError(
            f"Unexpected error contacting key service: {type(exc).__name__}. "
            "External scan blocked.",
            reason="service_unavailable",
        ) from exc

    if resp.status_code == 200:
        data = resp.json()
        return KeyConsumedReceipt(
            consumed_at=datetime.fromisoformat(data["consumed_at"]),
            message=data.get("message", "Key accepted."),
        )

    if resp.status_code == 401:
        try:
            detail = resp.json().get("detail", {})
            reason = detail.get("reason", "unknown") if isinstance(detail, dict) else "rejected"
            msg = detail.get("detail", "Key rejected.") if isinstance(detail, dict) else str(detail)
        except Exception:
            reason = "rejected"
            msg = "Key rejected by server."
        raise KeyValidationError(msg, reason=reason)

    if resp.status_code == 429:
        raise KeyValidationError(
            "Too many key validation attempts. Try again later.",
            reason="rate_limited",
        )

    if resp.status_code >= 500:
        raise KeyValidationError(
            f"Enterprise key service returned {resp.status_code}. "
            "External scan blocked (fail-closed policy).",
            reason="service_unavailable",
        )

    raise KeyValidationError(
        f"Unexpected response from key service (HTTP {resp.status_code}). "
        "External scan blocked.",
        reason="unexpected",
    )
