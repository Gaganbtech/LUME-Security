"""Tamper-evident audit log service.

Three security properties
─────────────────────────
1. HMAC-SHA256 per entry: every row is signed with LUME_KS_AUDIT_SECRET.
   If any field is altered in the DB, the HMAC check will fail.

2. Hash chaining: each entry stores SHA-256(prev_entry_hash ‖ current_payload).
   Deleting or reordering entries breaks the chain for all subsequent rows.

3. WORM storage: this module only ever calls INSERT.  There are no UPDATE or
   DELETE paths anywhere in the codebase for audit rows.  For a hardened
   deployment the DB user for the audit table can be restricted to INSERT+SELECT.
"""

import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from ks.config import settings
from ks.models import AuditLog

# ── Audit-specific secret (separate from session/JWT secret) ─────────────────
# In production, config.py enforces that LUME_KS_AUDIT_SECRET is set independently.
# In development, config.py falls back to LUME_KS_SECRET_KEY with a visible warning.
# This function reads the resolved value from settings — no direct env access here.

def _get_audit_secret() -> bytes:
    secret = settings.audit_secret
    if not secret:
        raise RuntimeError(
            "Audit secret is not configured. "
            "Set LUME_KS_AUDIT_SECRET (must be different from LUME_KS_SECRET_KEY)."
        )
    return secret.encode()


# ── Internal helpers ─────────────────────────────────────────────────────────

def _compute_payload_hash(
    event_type: str,
    actor_id: Optional[int],
    target_user_id: Optional[int],
    key_id: Optional[int],
    request_id: Optional[int],
    event_data: dict,
    timestamp: datetime,
) -> str:
    """SHA-256 of the canonical JSON representation of this entry's fields."""
    canonical = json.dumps(
        {
            "event_type": event_type,
            "actor_id": actor_id,
            "target_user_id": target_user_id,
            "key_id": key_id,
            "request_id": request_id,
            "event_data": event_data,
            "timestamp": timestamp.isoformat(),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def _compute_chain_hash(prev_entry_hash: str, payload_hash: str) -> str:
    """Chain: SHA-256(prev_hash ‖ payload_hash)."""
    combined = (prev_entry_hash + payload_hash).encode()
    return hashlib.sha256(combined).hexdigest()


def _compute_hmac(chain_hash: str) -> str:
    """HMAC-SHA256 over the chain hash using the audit secret."""
    return hmac.new(_get_audit_secret(), chain_hash.encode(), hashlib.sha256).hexdigest()


def _get_last_chain_hash(db: Session) -> str:
    """Return the chain hash of the most recent audit entry, or the genesis value."""
    last = db.query(AuditLog).order_by(AuditLog.id.desc()).first()
    if last is None:
        # Genesis hash: SHA-256("TRAVLUME_AUDIT_GENESIS")
        return hashlib.sha256(b"TRAVLUME_AUDIT_GENESIS").hexdigest()
    return last.chain_hash


# ── Public write API ─────────────────────────────────────────────────────────

def write_event(
    db: Session,
    event_type: str,
    actor_id: Optional[int] = None,
    target_user_id: Optional[int] = None,
    key_id: Optional[int] = None,
    request_id: Optional[int] = None,
    event_data: Optional[dict] = None,
) -> AuditLog:
    """Write a tamper-evident, hash-chained audit log entry.

    This is the ONLY function that inserts into the audit_logs table.
    Never call db.delete() or db.query(AuditLog).update() anywhere.

    Args:
        db:              SQLAlchemy session — caller must commit after.
        event_type:      e.g. 'account_signup', 'key_consumed'.
        actor_id:        User.id who performed the action (None for system).
        target_user_id:  User.id affected (None if not user-targeted).
        key_id:          EnterpriseKey.id involved (None if not key-related).
        request_id:      KeyRequest.id involved (None if not request-related).
        event_data:      Additional context dict (no plaintext keys!).

    Returns:
        The newly created AuditLog ORM instance (not yet committed).
    """
    if event_data is None:
        event_data = {}

    timestamp = datetime.now(timezone.utc)

    # 1. Payload hash — signs the content of this entry
    payload_hash = _compute_payload_hash(
        event_type, actor_id, target_user_id, key_id, request_id, event_data, timestamp
    )

    # 2. Chain hash — links to the previous entry
    prev_hash = _get_last_chain_hash(db)
    chain_hash = _compute_chain_hash(prev_hash, payload_hash)

    # 3. HMAC — signs the chain hash with the audit secret
    entry_hmac = _compute_hmac(chain_hash)

    entry = AuditLog(
        event_type=event_type,
        actor_id=actor_id,
        target_user_id=target_user_id,
        key_id=key_id,
        request_id=request_id,
        event_data=json.dumps(event_data, separators=(",", ":")),
        timestamp=timestamp,
        prev_entry_hash=prev_hash,
        chain_hash=chain_hash,
        entry_hmac=entry_hmac,
    )
    db.add(entry)
    # Caller is responsible for db.commit() to keep audit writes atomic
    # with the primary operation they describe.
    return entry


# ── Verification ────────────────────────────────────────────────────────────

def verify_chain(db: Session) -> dict:
    """Walk every audit entry in order and verify HMAC + chain integrity.

    Returns:
        {
            "total": int,
            "valid": bool,
            "first_broken_id": int | None,
            "errors": [{"id": int, "issue": str}, ...]
        }
    """
    entries = db.query(AuditLog).order_by(AuditLog.id.asc()).all()
    errors = []
    prev_hash = hashlib.sha256(b"TRAVLUME_AUDIT_GENESIS").hexdigest()

    for entry in entries:
        # Re-derive event_data dict
        try:
            event_data = json.loads(entry.event_data or "{}")
        except json.JSONDecodeError:
            event_data = {}

        timestamp = entry.timestamp
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)

        # Verify payload hash
        expected_payload = _compute_payload_hash(
            entry.event_type,
            entry.actor_id,
            entry.target_user_id,
            entry.key_id,
            entry.request_id,
            event_data,
            timestamp,
        )
        expected_chain = _compute_chain_hash(prev_hash, expected_payload)
        expected_hmac = _compute_hmac(expected_chain)

        issues = []
        if entry.prev_entry_hash != prev_hash:
            issues.append("chain_link_broken")
        if entry.chain_hash != expected_chain:
            issues.append("chain_hash_mismatch")
        if not hmac.compare_digest(entry.entry_hmac, expected_hmac):
            issues.append("hmac_invalid")

        if issues:
            errors.append({"id": entry.id, "event_type": entry.event_type, "issues": issues})

        # Advance chain regardless — so we can find ALL broken entries
        prev_hash = entry.chain_hash

    first_broken_id = errors[0]["id"] if errors else None
    return {
        "total": len(entries),
        "valid": len(errors) == 0,
        "first_broken_id": first_broken_id,
        "errors": errors,
    }
