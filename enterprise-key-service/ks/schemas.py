"""Pydantic request / response schemas. Plaintext key never appears except at issuance."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

# ── Auth ──────────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=256)


class TokenResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in: int
    role: str


# ── Key request (user submits) ────────────────────────────────────────────────

class KeyRequestCreate(BaseModel):
    """User submits a key request."""
    reason: str = Field(default="", max_length=500, description="Optional reason for the request")


class KeyRequestResponse(BaseModel):
    """Status of a key request."""
    id: int
    status: Literal["pending", "approved", "rejected"]
    requested_at: datetime
    reviewed_at: datetime | None
    rejection_reason: str | None
    issued_key_id: int | None


class KeyRequestListResponse(BaseModel):
    requests: list[KeyRequestResponse]


# ── Admin: review requests ────────────────────────────────────────────────────

class RequestRejectRequest(BaseModel):
    reason: str = Field(..., min_length=1, max_length=500)


class RequestApproveResponse(BaseModel):
    """Returned to admin after approving a request."""
    request_id: int
    status: Literal["approved"] = "approved"
    key_id: str
    issued_to: str


# ── Admin: list all requests ──────────────────────────────────────────────────

class AdminKeyRequestView(BaseModel):
    """Admin's view of a key request — includes the requesting user's name."""
    id: int
    user_id: int
    username: str
    status: Literal["pending", "approved", "rejected"]
    requested_at: datetime
    reviewed_by: str | None
    reviewed_at: datetime | None
    rejection_reason: str | None
    issued_key_id: int | None


class AdminRequestListResponse(BaseModel):
    requests: list[AdminKeyRequestView]


# ── Admin: user management ────────────────────────────────────────────────────

class AdminUserView(BaseModel):
    id: int
    username: str
    email: str
    role: str
    is_active: bool
    created_at: datetime
    key_count: int = 0
    pending_request_count: int = 0


class AdminUserListResponse(BaseModel):
    users: list[AdminUserView]


class ChangeRoleRequest(BaseModel):
    role: Literal["admin", "enterprise_user"]


# ── Admin: key audit ─────────────────────────────────────────────────────────

class AdminKeyView(BaseModel):
    """Admin's view of all keys — includes owner name."""
    id: int
    key_id: str
    owner_username: str
    is_consumed: bool
    is_revoked: bool
    created_at: datetime
    consumed_at: datetime | None
    consumed_by_scan_target: str | None
    expires_at: datetime
    revoked_at: datetime | None
    revoked_by_username: str | None


class AdminKeyListResponse(BaseModel):
    keys: list[AdminKeyView]


# ── Key issuance (admin self-request or auto-approve) ─────────────────────────

class KeyIssueResponse(BaseModel):
    """Returned exactly once at issuance. The plaintext key is never returned again."""
    key: str
    key_id: str
    created_at: datetime


# ── Key validation (CLI → service) ────────────────────────────────────────────

class KeyValidateRequest(BaseModel):
    key: str = Field(..., min_length=10, max_length=128)
    scan_target: str = Field(..., min_length=1, max_length=2048)


class KeyValidateResponse(BaseModel):
    status: Literal["consumed"]
    consumed_at: datetime
    message: str


# ── Key metadata (dashboard) ──────────────────────────────────────────────────

class KeyMetadata(BaseModel):
    key_id: str
    is_consumed: bool
    is_revoked: bool
    created_at: datetime
    consumed_at: datetime | None
    consumed_by_scan_target: str | None
    expires_at: datetime


class KeyListResponse(BaseModel):
    keys: list[KeyMetadata]


# ── Account creation (seed CLI) ───────────────────────────────────────────────

class CreateUserRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    email: str = Field(..., description="Email address for the new account")
    password: str = Field(..., min_length=12, max_length=256)
    role: Literal["admin", "enterprise_user"] = "enterprise_user"
