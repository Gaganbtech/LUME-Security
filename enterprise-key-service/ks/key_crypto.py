"""Fernet authenticated encryption for pending display keys.

Why this exists
───────────────
When an admin approves a key request, the plaintext key must be shown to
the requesting user exactly once on their next dashboard visit.  Before this
fix the plaintext was written directly to key_requests.pending_display_key.

Now the plaintext is encrypted with Fernet before it reaches the database.
Fernet provides AES-128-CBC + HMAC-SHA256 authentication, so the ciphertext
cannot be decrypted or forged without LUME_KS_ENCRYPTION_KEY.

The encryption key is separate from the JWT secret and the audit HMAC secret
so that rotation of one does not invalidate the others.

Key lifecycle
─────────────
1. Admin approves request.
2. Server generates 43-char plaintext key.
3. encrypt_pending_key(plaintext) → b64-encoded Fernet token (~200 chars).
4. Token stored in key_requests.pending_display_key (column widened to 512).
5. User visits dashboard for the first time after approval.
6. decrypt_pending_key(token) → plaintext returned to user in HTML.
7. pending_display_key immediately set to NULL and committed.

If LUME_KS_ENCRYPTION_KEY is not set the application refuses to start
(in production) or raises at the point of use (in tests that set the env var).
"""

import os
from typing import Optional


def _get_fernet() -> object:
    """Return a configured Fernet instance.

    Raises RuntimeError if LUME_KS_ENCRYPTION_KEY is not set or invalid.
    """
    try:
        from cryptography.fernet import Fernet, InvalidToken  # noqa: F401
    except ImportError as exc:
        raise RuntimeError(
            "The 'cryptography' package is required. Install it with: "
            "pip install cryptography"
        ) from exc

    raw = os.environ.get("LUME_KS_ENCRYPTION_KEY", "").strip()
    if not raw:
        raise RuntimeError(
            "LUME_KS_ENCRYPTION_KEY is not set. "
            "Generate one with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
        )

    try:
        key_bytes = raw.encode() if isinstance(raw, str) else raw
        return Fernet(key_bytes)
    except Exception as exc:
        raise RuntimeError(
            f"LUME_KS_ENCRYPTION_KEY is invalid: {exc}. "
            "Generate a valid key with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
        ) from exc


def encrypt_pending_key(plaintext: str) -> str:
    """Encrypt a plaintext enterprise key for temporary storage.

    Returns a URL-safe base64 Fernet token (safe for VARCHAR storage).
    Never stores the plaintext.
    """
    fernet = _get_fernet()
    token: bytes = fernet.encrypt(plaintext.encode("utf-8"))
    return token.decode("ascii")


def decrypt_pending_key(token: str) -> Optional[str]:
    """Decrypt and return the plaintext key from a stored token.

    Returns None if the token is invalid, expired, or tampered with.
    Never raises — returns None on any failure so callers handle it safely.
    """
    if not token:
        return None
    try:
        fernet = _get_fernet()
        plaintext_bytes: bytes = fernet.decrypt(token.encode("ascii"))
        return plaintext_bytes.decode("utf-8")
    except Exception:
        # InvalidToken, bad encoding, wrong key, etc.
        return None


def is_encrypted_token(value: str) -> bool:
    """Heuristic: Fernet tokens start with 'gAAA' (base64 of version byte 0x80).

    Used during migration to distinguish existing plaintext keys from
    already-encrypted tokens so we do not double-encrypt.
    """
    return value.startswith("gAAA")
