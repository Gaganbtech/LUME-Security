"""Password hashing and JWT utilities."""

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
from jose import JWTError, jwt

from ks.config import settings

# ── Passwords (bcrypt direct — avoids passlib/bcrypt version compat issues) ──

def hash_password(plain: str) -> str:
    """Hash a plaintext password with bcrypt."""
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a plaintext password against a bcrypt hash."""
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


# ── JWT tokens ────────────────────────────────────────────────────────────────

def create_access_token(subject: str, expires_seconds: Optional[int] = None) -> str:
    expire_secs = expires_seconds if expires_seconds is not None else settings.token_expire_seconds
    expire = datetime.now(timezone.utc) + timedelta(seconds=expire_secs)
    payload = {"sub": subject, "exp": expire}
    return jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)


def decode_access_token(token: str) -> Optional[str]:
    """Return the subject (username) or None if the token is invalid/expired."""
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        return payload.get("sub")
    except JWTError:
        return None


# ── Enterprise key generation & hashing ──────────────────────────────────────

def generate_enterprise_key() -> str:
    """Generate a 256-bit URL-safe enterprise key. Never stored in plaintext."""
    return secrets.token_urlsafe(32)  # 43 chars base64url


def hash_enterprise_key(plaintext_key: str) -> str:
    """Return the SHA-256 hex digest of a plaintext enterprise key."""
    return hashlib.sha256(plaintext_key.encode()).hexdigest()


def key_id_from_hash(key_hash: str) -> str:
    """Derive a short display identifier from the key hash."""
    return key_hash[:8]


# ── Key expiry ────────────────────────────────────────────────────────────────

KEY_VALIDITY_DAYS = 30


def compute_key_expiry(created_at: datetime) -> datetime:
    """Return the expiry datetime 30 days after creation."""
    return created_at + timedelta(days=KEY_VALIDITY_DAYS)


def is_key_expired(expires_at: datetime | None, now: datetime | None = None) -> bool:
    """Check if a key has expired. Returns False if expires_at is None."""
    if expires_at is None:
        return False
    current = now or datetime.now(timezone.utc)
    # Handle both tz-aware and tz-naive datetimes
    if expires_at.tzinfo is None and current.tzinfo is not None:
        current = current.replace(tzinfo=None)
    elif expires_at.tzinfo is not None and current.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=None)
    return current > expires_at
