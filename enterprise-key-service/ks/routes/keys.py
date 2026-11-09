"""Key request, issuance, listing, and validation routes.

Key changes from original:
- Users submit key REQUESTS (not self-issue); admin approves/rejects
- Admins can self-request (auto-approved, key generated immediately)
- Key validation now checks is_revoked and expires_at
- Dashboard shows request status + one-time display of approved keys
"""

from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from ks.audit import write_event
from ks.auth import (
    compute_key_expiry,
    generate_enterprise_key,
    hash_enterprise_key,
    key_id_from_hash,
)
from ks.database import get_db
from ks.dependencies import get_current_user, get_current_user_from_bearer
from ks.key_consume import KeyNotFound, consume_key_atomically
from ks.models import EnterpriseKey, KeyRequest, User
from ks.schemas import (
    KeyIssueResponse,
    KeyListResponse,
    KeyMetadata,
    KeyRequestResponse,
    KeyValidateRequest,
    KeyValidateResponse,
)

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))


def _enrich_keys(keys) -> list:
    """Add a computed is_expired flag to each key object for template rendering."""
    now = datetime.now(timezone.utc)
    enriched = []
    for k in keys:
        exp = k.expires_at
        if exp is not None:
            # Normalise tz-awareness before comparing
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            expired = now > exp
        else:
            expired = False
        # Attach as a plain dict so templates don't call ORM methods
        enriched.append({
            "key_id": k.key_id,
            "is_consumed": k.is_consumed,
            "is_revoked": k.is_revoked,
            "is_expired": expired,
            "created_at": k.created_at,
            "consumed_at": k.consumed_at,
            "consumed_by_scan_target": k.consumed_by_scan_target,
            "expires_at": k.expires_at,
        })
    return enriched


# ── Dashboard (browser) ───────────────────────────────────────────────────────

@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    keys = (
        db.query(EnterpriseKey)
        .filter(EnterpriseKey.owner_id == current_user.id)
        .order_by(EnterpriseKey.created_at.desc())
        .all()
    )

    # Check for approved requests with pending one-time key display
    one_time_key = None
    approved_with_pending = (
        db.query(KeyRequest)
        .filter(
            KeyRequest.user_id == current_user.id,
            KeyRequest.status == "approved",
            KeyRequest.pending_display_key.isnot(None),
        )
        .first()
    )
    if approved_with_pending:
        raw_stored = approved_with_pending.pending_display_key
        # Decrypt if encrypted, pass through if plaintext (dev without enc key)
        from ks.key_crypto import decrypt_pending_key, is_encrypted_token
        if raw_stored and is_encrypted_token(raw_stored):
            one_time_key = decrypt_pending_key(raw_stored)
        else:
            one_time_key = raw_stored  # dev fallback: plaintext
        # Clear immediately regardless of decrypt success
        approved_with_pending.pending_display_key = None
        db.commit()

    # User's requests (for status display)
    user_requests = (
        db.query(KeyRequest)
        .filter(KeyRequest.user_id == current_user.id)
        .order_by(KeyRequest.requested_at.desc())
        .all()
    )

    # Check if user has a pending request (can't submit another)
    has_pending = any(r.status == "pending" for r in user_requests)

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "user": current_user,
            "keys": _enrich_keys(keys),
            "one_time_key": one_time_key,
            "requests": user_requests,
            "has_pending": has_pending,
            "is_admin": current_user.role == "admin",
            "is_approved": current_user.is_approved,
        },
    )


# ── Key request (user submits) ────────────────────────────────────────────────

@router.post("/keys/request", response_class=HTMLResponse)
async def request_key_form(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Browser form: user submits a key request."""
    # Block unapproved users — server-side check, not just UI
    if not current_user.is_approved:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your account has not been approved yet. Wait for an admin to approve it before requesting keys.",
        )

    # One pending request at a time
    existing_pending = (
        db.query(KeyRequest)
        .filter(KeyRequest.user_id == current_user.id, KeyRequest.status == "pending")
        .first()
    )
    if existing_pending:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="You already have a pending key request. Wait for it to be reviewed.",
        )

    # Admin self-request: auto-approve and generate immediately
    if current_user.role == "admin":
        plaintext = generate_enterprise_key()
        key_hash = hash_enterprise_key(plaintext)
        kid = key_id_from_hash(key_hash)
        now = datetime.now(timezone.utc)

        new_key = EnterpriseKey(
            key_hash=key_hash,
            key_id=kid,
            owner_id=current_user.id,
            is_consumed=False,
            is_revoked=False,
            created_at=now,
            expires_at=compute_key_expiry(now),
        )
        db.add(new_key)
        db.commit()
        db.refresh(new_key)

        # Create an auto-approved request record
        req = KeyRequest(
            user_id=current_user.id,
            status="approved",
            requested_at=now,
            reviewed_by=current_user.id,
            reviewed_at=now,
            issued_key_id=new_key.id,
        )
        db.add(req)
        db.commit()

        # Show key via session (same as self-issue)
        request.session["one_time_key"] = plaintext
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)

    # Regular user: create pending request
    new_request = KeyRequest(
        user_id=current_user.id,
        status="pending",
        requested_at=datetime.now(timezone.utc),
    )
    db.add(new_request)
    db.commit()
    db.refresh(new_request)
    write_event(db, "key_requested",
                actor_id=current_user.id, target_user_id=current_user.id,
                request_id=new_request.id)
    db.commit()
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)


# ── JSON API — key request ────────────────────────────────────────────────────

@router.post("/api/keys/request", response_model=KeyRequestResponse)
async def api_request_key(
    current_user: User = Depends(get_current_user_from_bearer),
    db: Session = Depends(get_db),
):
    """Submit a key request via JSON API. One pending request per user."""
    if not current_user.is_approved:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account pending admin approval. Request keys after an admin approves your account.",
        )
    existing_pending = (
        db.query(KeyRequest)
        .filter(KeyRequest.user_id == current_user.id, KeyRequest.status == "pending")
        .first()
    )
    if existing_pending:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="You already have a pending key request.",
        )

    # Admin self-request: auto-approve + generate
    if current_user.role == "admin":
        plaintext = generate_enterprise_key()
        key_hash = hash_enterprise_key(plaintext)
        kid = key_id_from_hash(key_hash)
        now = datetime.now(timezone.utc)

        new_key = EnterpriseKey(
            key_hash=key_hash,
            key_id=kid,
            owner_id=current_user.id,
            is_consumed=False,
            is_revoked=False,
            created_at=now,
            expires_at=compute_key_expiry(now),
        )
        db.add(new_key)
        db.commit()
        db.refresh(new_key)

        req = KeyRequest(
            user_id=current_user.id,
            status="approved",
            requested_at=now,
            reviewed_by=current_user.id,
            reviewed_at=now,
            issued_key_id=new_key.id,
        )
        db.add(req)
        db.commit()
        db.refresh(req)

        # Return both the request status and the one-time key
        return KeyRequestResponse(
            id=req.id,
            status="approved",
            requested_at=req.requested_at,
            reviewed_at=req.reviewed_at,
            rejection_reason=None,
            issued_key_id=req.issued_key_id,
        )

    # Regular user request
    new_request = KeyRequest(
        user_id=current_user.id,
        status="pending",
        requested_at=datetime.now(timezone.utc),
    )
    db.add(new_request)
    db.commit()
    db.refresh(new_request)

    return KeyRequestResponse(
        id=new_request.id,
        status="pending",
        requested_at=new_request.requested_at,
        reviewed_at=None,
        rejection_reason=None,
        issued_key_id=None,
    )


# ── JSON API — list own requests ──────────────────────────────────────────────

@router.get("/api/keys/requests/me", response_model=list[KeyRequestResponse])
async def list_my_requests(
    current_user: User = Depends(get_current_user_from_bearer),
    db: Session = Depends(get_db),
):
    requests = (
        db.query(KeyRequest)
        .filter(KeyRequest.user_id == current_user.id)
        .order_by(KeyRequest.requested_at.desc())
        .all()
    )
    return [
        KeyRequestResponse(
            id=r.id,
            status=r.status,
            requested_at=r.requested_at,
            reviewed_at=r.reviewed_at,
            rejection_reason=r.rejection_reason,
            issued_key_id=r.issued_key_id,
        )
        for r in requests
    ]


# ── JSON API — admin self-issue (kept for backward compat, admin only) ────────

@router.post("/api/keys/issue", response_model=KeyIssueResponse, status_code=status.HTTP_201_CREATED)
async def api_issue_key(
    current_user: User = Depends(get_current_user_from_bearer),
    db: Session = Depends(get_db),
):
    """Issue a new enterprise key. Admin only — regular users must request."""

    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can self-issue keys. Use POST /api/keys/request to request a key.",
        )

    plaintext = generate_enterprise_key()
    key_hash = hash_enterprise_key(plaintext)
    kid = key_id_from_hash(key_hash)
    now = datetime.now(timezone.utc)

    new_key = EnterpriseKey(
        key_hash=key_hash,
        key_id=kid,
        owner_id=current_user.id,
        is_consumed=False,
        is_revoked=False,
        created_at=now,
        expires_at=compute_key_expiry(now),
    )
    db.add(new_key)
    db.commit()

    return KeyIssueResponse(key=plaintext, key_id=kid, created_at=now)


# ── JSON API — list own keys (metadata only) ──────────────────────────────────

@router.get("/api/keys/me", response_model=KeyListResponse)
async def list_my_keys(
    current_user: User = Depends(get_current_user_from_bearer),
    db: Session = Depends(get_db),
):
    keys = (
        db.query(EnterpriseKey)
        .filter(EnterpriseKey.owner_id == current_user.id)
        .order_by(EnterpriseKey.created_at.desc())
        .all()
    )
    return KeyListResponse(
        keys=[
            KeyMetadata(
                key_id=k.key_id,
                is_consumed=k.is_consumed,
                is_revoked=k.is_revoked,
                created_at=k.created_at,
                consumed_at=k.consumed_at,
                consumed_by_scan_target=k.consumed_by_scan_target,
                expires_at=k.expires_at,
            )
            for k in keys
        ]
    )


# ── JSON API — validate key (CLI) ─────────────────────────────────────────────

@router.post("/keys/validate")
async def validate_key(
    body: KeyValidateRequest,
    db: Session = Depends(get_db),
):
    """Atomically consume an enterprise key for one external scan.

    Uses dialect-aware atomic consumption:
    - PostgreSQL: single UPDATE...WHERE is_consumed=false RETURNING
    - SQLite: SELECT + UPDATE (serialised by SQLite write lock)

    The key is hashed server-side; plaintext is never logged or stored.
    """
    try:
        consumed = consume_key_atomically(db, body.key, body.scan_target)
    except KeyNotFound as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"status": "rejected", "reason": exc.reason, "detail": exc.msg},
        )

    db.commit()

    write_event(
        db, "key_consumed",
        actor_id=None,
        target_user_id=consumed["owner_id"],
        key_id=consumed["id"],
        event_data={"scan_target": body.scan_target[:256], "key_id_short": consumed["key_id"]},
    )
    db.commit()

    return KeyValidateResponse(
        status="consumed",
        consumed_at=consumed["consumed_at"],
        message="Key accepted. One-time authorization granted.",
    )
