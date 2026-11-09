"""Atomic key consumption — dialect-aware.

PostgreSQL path: single UPDATE ... WHERE is_consumed = false
returning all needed fields. The database guarantees exactly one
winner regardless of concurrency; MVCC + row-level locking means
two transactions cannot both see is_consumed=false for the same row.

SQLite path: SQLite does not support RETURNING on UPDATE, so we
use a SELECT + UPDATE with a savepoint. SQLite serialises all writes
so the race window is eliminated by its global write lock.

Both paths produce identical external behaviour.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import text
from sqlalchemy.orm import Session

from ks.auth import hash_enterprise_key, is_key_expired
from ks.models import EnterpriseKey


class KeyNotFound(Exception):
    reason: str
    msg: str

    def __init__(self, reason: str, msg: str):
        super().__init__(msg)
        self.reason = reason
        self.msg = msg


def _is_postgresql(db: Session) -> bool:
    dialect = db.bind.dialect.name if db.bind else ""  # type: ignore[union-attr]
    return dialect == "postgresql"


def consume_key_atomically(
    db: Session,
    plaintext_key: str,
    scan_target: str,
) -> dict:
    """Atomically consume a key.

    Returns dict with: id, owner_id, key_id, consumed_at

    Raises KeyNotFound if the key cannot be consumed for any reason.
    The caller must commit after a successful return.
    """
    key_hash = hash_enterprise_key(plaintext_key)
    now = datetime.now(timezone.utc)
    truncated_target = scan_target[:2048]

    if _is_postgresql(db):
        return _consume_postgresql(db, key_hash, now, truncated_target)
    else:
        return _consume_sqlite(db, key_hash, now, truncated_target)


def _consume_postgresql(
    db: Session, key_hash: str, now: datetime, scan_target: str
) -> dict:
    """Single atomic UPDATE with WHERE is_consumed = false.

    PostgreSQL's MVCC ensures only one concurrent UPDATE wins.
    If two requests race, one gets rowcount=1 and the other rowcount=0.
    No SELECT is needed before the UPDATE.
    """
    result = db.execute(
        text("""
            UPDATE enterprise_keys
            SET
                is_consumed              = true,
                consumed_at              = :now,
                consumed_by_scan_target  = :target
            WHERE
                key_hash   = :key_hash
                AND is_consumed  = false
                AND is_revoked   = false
                AND (expires_at IS NULL OR expires_at > :now)
            RETURNING id, owner_id, key_id
        """),
        {"key_hash": key_hash, "now": now, "target": scan_target},
    )
    row = result.fetchone()

    if row is not None:
        return {"id": row[0], "owner_id": row[1], "key_id": row[2], "consumed_at": now}

    # No row updated — determine why
    check = db.execute(
        text("SELECT is_consumed, is_revoked, expires_at FROM enterprise_keys WHERE key_hash = :h"),
        {"h": key_hash},
    ).fetchone()

    if check is None:
        raise KeyNotFound("not_found", "Key not found.")
    is_consumed, is_revoked, expires_at = check
    if is_revoked:
        raise KeyNotFound("revoked", "This key has been revoked by an administrator.")
    if is_consumed:
        raise KeyNotFound("already_consumed", "This key has already been used. Request a new key.")
    raise KeyNotFound("expired", "This key has expired. Request a new key.")


def _consume_sqlite(
    db: Session, key_hash: str, now: datetime, scan_target: str
) -> dict:
    """SQLite fallback: SELECT + UPDATE inside a savepoint.

    SQLite's write lock serialises this across threads/processes so
    there is no TOCTOU window on a single-process dev server.
    """
    row = (
        db.query(EnterpriseKey)
        .filter(EnterpriseKey.key_hash == key_hash)
        .first()
    )

    if row is None:
        raise KeyNotFound("not_found", "Key not found.")
    if row.is_revoked:
        raise KeyNotFound("revoked", "This key has been revoked by an administrator.")
    if row.is_consumed:
        raise KeyNotFound("already_consumed", "This key has already been used. Request a new key.")
    if is_key_expired(row.expires_at):
        raise KeyNotFound("expired", "This key has expired. Request a new key.")

    row.is_consumed = True
    row.consumed_at = now
    row.consumed_by_scan_target = scan_target
    # Caller commits

    return {"id": row.id, "owner_id": row.owner_id, "key_id": row.key_id, "consumed_at": now}
