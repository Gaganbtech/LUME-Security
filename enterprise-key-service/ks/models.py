"""SQLAlchemy ORM models for users, enterprise keys, and key requests."""

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ks.database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    # Account approval: new signups start as is_approved=False until an admin approves them.
    # Seeded/admin accounts start as is_approved=True.
    is_approved: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    # RBAC: 'admin' or 'enterprise_user' (default for backward compatibility)
    role: Mapped[str] = mapped_column(String(32), default="enterprise_user", nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)

    keys: Mapped[list["EnterpriseKey"]] = relationship("EnterpriseKey", back_populates="owner", foreign_keys="EnterpriseKey.owner_id")
    requests: Mapped[list["KeyRequest"]] = relationship("KeyRequest", back_populates="user", foreign_keys="KeyRequest.user_id")


class EnterpriseKey(Base):
    __tablename__ = "enterprise_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    key_id: Mapped[str] = mapped_column(String(16), nullable=False)
    owner_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    is_consumed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    is_revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    consumed_by_scan_target: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    # Key expiry: 30 days from creation if unused. Set explicitly at creation.
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by: Mapped[int | None] = mapped_column(Integer, ForeignKey("users.id"), nullable=True)

    owner: Mapped["User"] = relationship("User", back_populates="keys", foreign_keys=[owner_id])


class KeyRequest(Base):
    """A user's request for an enterprise key, reviewed by an admin."""
    __tablename__ = "key_requests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(20), default="pending", nullable=False, index=True)
    # 'pending', 'approved', 'rejected'
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    reviewed_by: Mapped[int | None] = mapped_column(Integer, ForeignKey("users.id"), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rejection_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)
    # The key created when this request is approved
    issued_key_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("enterprise_keys.id"), nullable=True)
    # Temporary encrypted storage for one-time display after admin approval.
    # Encrypted with Fernet (LUME_KS_ENCRYPTION_KEY) before persisting.
    # Cleared immediately after the owner reads it on their dashboard.
    # Column widened to 512 to hold Fernet tokens (~200 chars).
    pending_display_key: Mapped[str | None] = mapped_column(String(512), nullable=True)

    user: Mapped["User"] = relationship("User", back_populates="requests", foreign_keys=[user_id])
    reviewer: Mapped["User | None"] = relationship("User", foreign_keys=[reviewed_by])


class AuditLog(Base):
    """Tamper-evident, hash-chained, WORM audit log.

    NEVER update or delete rows in this table.
    INSERT only via ks.audit.write_event().
    """
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    # Event classification
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    # Who did it (None = system action)
    actor_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("users.id"), nullable=True)
    # Who was affected (None if not user-targeted)
    target_user_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("users.id"), nullable=True)
    # Related objects
    key_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    request_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Additional JSON context — no plaintext keys ever stored here
    event_data: Mapped[str | None] = mapped_column(String(4096), nullable=True)
    # When it happened
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False, index=True)
    # Tamper-evidence fields
    prev_entry_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    chain_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    entry_hmac: Mapped[str] = mapped_column(String(64), nullable=False)
