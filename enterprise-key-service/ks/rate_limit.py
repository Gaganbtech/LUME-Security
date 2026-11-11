"""Rate limiter instance shared across all route modules.

Defined in a separate module to avoid circular imports between
ks.main (which imports routers) and ks.routes.* (which need the limiter).

X-Forwarded-For security analysis
───────────────────────────────────
Render's official feedback page confirms (https://feedback.render.com/features/p/send-the-correct-x-forwarded-for):

  "Render does not clear or reset any passed-in X-Forwarded-For header
   (it only appends to it), so a client could spoof its IP by setting
   this header itself."

This means:

  Client sends:   GET / HTTP/1.1
                  X-Forwarded-For: 1.2.3.4   ← attacker-controlled

  Render appends: X-Forwarded-For: 1.2.3.4, <render-edge-ip>

  Result in app:  "1.2.3.4, <render-edge-ip>"

Reading the FIRST entry ("1.2.3.4") is UNSAFE — the attacker controls it.

Correct approach — trusted proxy hop count
───────────────────────────────────────────
The last N entries in X-Forwarded-For are appended by the N trusted proxy
hops between the application and the client. The entry at position [-N]
from the right is the first entry that a trusted proxy saw, and cannot
have been forged by the original client.

For Render (1 proxy hop between internet and app):
  - Right-most entry  [-1]: the IP Render's edge appended — this is the
    real client IP as seen by Render. Cannot be forged.
  - Everything before: potentially attacker-controlled.

For Render + Cloudflare (2 proxy hops):
  - Entry at [-2]: Cloudflare's view of the client IP.
  - Entry at [-1]: Render's view (may be a Cloudflare edge IP).

LUME_KS_PROXY_COUNT controls the trust depth (default: 1 for Render alone).

Fail-safe default
──────────────────
In development (LUME_KS_ENV != production OR LUME_KS_TRUST_PROXY = false):
  X-Forwarded-For is completely ignored. The direct connection IP is used.
  This prevents local test clients or curl from spoofing the header.

In production (LUME_KS_ENV = production OR LUME_KS_TRUST_PROXY = true):
  The entry at position [-LUME_KS_PROXY_COUNT] from the right is used.
  With LUME_KS_PROXY_COUNT=1 (default), this is the rightmost entry
  (appended by Render) — not the leftmost (attacker-controlled).
"""

import os

from slowapi import Limiter


def _is_trust_proxy() -> bool:
    """Determine whether to trust X-Forwarded-For.

    Explicit env var LUME_KS_TRUST_PROXY takes precedence.
    Otherwise, trust in production, distrust in development.
    """
    explicit = os.getenv("LUME_KS_TRUST_PROXY", "").strip().lower()
    if explicit in ("true", "1", "yes"):
        return True
    if explicit in ("false", "0", "no"):
        return False
    # Follow LUME_KS_ENV — safe default is distrust in development
    return os.getenv("LUME_KS_ENV", "development").lower() == "production"


def _proxy_count() -> int:
    """Return the number of trusted proxy hops between internet and app.

    Default: 1 (Render's edge proxy only).
    If using Render + Cloudflare: set LUME_KS_PROXY_COUNT=2.

    This determines which entry in X-Forwarded-For is trusted:
    with count=N, use entries[-N] (the N-th from the right).
    """
    try:
        count = int(os.getenv("LUME_KS_PROXY_COUNT", "1"))
        return max(1, count)   # minimum 1, never 0
    except (TypeError, ValueError):
        return 1


def _get_client_ip(request) -> str:
    """Extract client IP for rate limiting.

    Security model:
    - In untrusted mode (development): ignore X-Forwarded-For entirely.
      Uses request.client.host (the direct TCP connection IP).
      This prevents X-Forwarded-For injection from test clients or curl.

    - In trusted proxy mode (production): read X-Forwarded-For and use
      the entry at position [-LUME_KS_PROXY_COUNT] from the RIGHT.
      This is the IP appended by the last trusted proxy (Render), which
      the client cannot forge because Render appends AFTER receiving.

    Example with LUME_KS_PROXY_COUNT=1 (default, Render only):
      X-Forwarded-For: "attacker-ip, real-client-ip"
                                       ^^^^^^^^^^^^^^^^^
                                       entries[-1] — Render-appended, trusted

    Example with LUME_KS_PROXY_COUNT=2 (Render + Cloudflare):
      X-Forwarded-For: "attacker-ip, cloudflare-sees-ip, render-sees-ip"
                                     ^^^^^^^^^^^^^^^^^^^^^
                                     entries[-2] — Cloudflare-appended, trusted

    If fewer entries exist than LUME_KS_PROXY_COUNT (misconfiguration),
    falls back to request.client.host (safe fallback — never fails open).
    """
    if not _is_trust_proxy():
        # Untrusted / development: always use direct connection IP
        return request.client.host if request.client else "0.0.0.0"

    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        entries = [e.strip() for e in forwarded.split(",") if e.strip()]
        count = _proxy_count()
        if len(entries) >= count:
            # Safe: use the N-th entry from the right
            return entries[-count]
        # Fewer entries than expected proxy hops — misconfiguration or no proxies.
        # Fall back to direct connection rather than trusting a potentially
        # forged leftmost entry.

    # No X-Forwarded-For header or insufficient entries
    return request.client.host if request.client else "0.0.0.0"


limiter = Limiter(key_func=_get_client_ip)
