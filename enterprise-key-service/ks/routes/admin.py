"""Admin routes: request review, user management, key audit, revocation.

All endpoints require the 'admin' role, enforced server-side via require_role().
Admins cannot change their own role or deactivate themselves.
At least one active admin must remain at all times.
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
from ks.dependencies import (
    require_role,
    require_role_cookie,
)
from ks.models import EnterpriseKey, KeyRequest, User
from ks.schemas import (
    AdminKeyListResponse,
    AdminKeyRequestView,
    AdminKeyView,
    AdminRequestListResponse,
    AdminUserListResponse,
    AdminUserView,
    ChangeRoleRequest,
    RequestApproveResponse,
    RequestRejectRequest,
)

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))


# ── Admin dashboard (browser) ─────────────────────────────────────────────────

@router.get("/admin/dashboard", response_class=HTMLResponse)
async def admin_dashboard(
    request: Request,
    current_user: User = Depends(require_role_cookie("admin")),
    db: Session = Depends(get_db),
):
    # Pending requests for review
    pending_requests = (
        db.query(KeyRequest)
        .filter(KeyRequest.status == "pending")
        .order_by(KeyRequest.requested_at.desc())
        .all()
    )

    # Users awaiting account approval (signed up but not yet approved)
    pending_account_users = (
        db.query(User)
        .filter(User.is_approved.is_(False), User.is_active.is_(True))
        .order_by(User.created_at.desc())
        .all()
    )

    # All users
    users = db.query(User).order_by(User.created_at.desc()).all()

    # All keys (audit view)
    all_keys = (
        db.query(EnterpriseKey)
        .order_by(EnterpriseKey.created_at.desc())
        .limit(100)
        .all()
    )

    # Build request views with usernames
    request_views = []
    for req in pending_requests:
        req_user = db.query(User).filter(User.id == req.user_id).first()
        request_views.append({
            "id": req.id,
            "username": req_user.username if req_user else "unknown",
            "requested_at": req.requested_at,
        })

    # Build key views with owner usernames
    key_views = []
    for k in all_keys:
        owner = db.query(User).filter(User.id == k.owner_id).first()
        revoker = db.query(User).filter(User.id == k.revoked_by).first() if k.revoked_by else None
        key_views.append({
            "id": k.id,
            "key_id": k.key_id,
            "owner_username": owner.username if owner else "unknown",
            "is_consumed": k.is_consumed,
            "is_revoked": k.is_revoked,
            "created_at": k.created_at,
            "consumed_at": k.consumed_at,
            "consumed_by_scan_target": k.consumed_by_scan_target,
            "expires_at": k.expires_at,
            "revoked_at": k.revoked_at,
            "revoked_by_username": revoker.username if revoker else None,
        })

    # Build user views with counts
    user_views = []
    for u in users:
        key_count = db.query(EnterpriseKey).filter(EnterpriseKey.owner_id == u.id).count()
        pending_count = db.query(KeyRequest).filter(
            KeyRequest.user_id == u.id, KeyRequest.status == "pending"
        ).count()
        user_views.append({
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "role": u.role,
            "is_active": u.is_active,
            "is_approved": u.is_approved,
            "created_at": u.created_at,
            "key_count": key_count,
            "pending_request_count": pending_count,
        })

    return templates.TemplateResponse(
        request=request,
        name="admin_dashboard.html",
        context={
            "user": current_user,
            "pending_requests": request_views,
            "pending_account_users": pending_account_users,
            "users": user_views,
            "keys": key_views,
        },
    )


# ── API: list all requests (admin) ─────────────────────────────────────────────

@router.get("/api/admin/requests", response_model=AdminRequestListResponse)
async def list_all_requests(
    status_filter: str | None = None,
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    query = db.query(KeyRequest)
    if status_filter:
        query = query.filter(KeyRequest.status == status_filter)
    requests = query.order_by(KeyRequest.requested_at.desc()).all()

    views = []
    for r in requests:
        req_user = db.query(User).filter(User.id == r.user_id).first()
        reviewer = db.query(User).filter(User.id == r.reviewed_by).first() if r.reviewed_by else None
        views.append(AdminKeyRequestView(
            id=r.id,
            user_id=r.user_id,
            username=req_user.username if req_user else "unknown",
            status=r.status,
            requested_at=r.requested_at,
            reviewed_by=reviewer.username if reviewer else None,
            reviewed_at=r.reviewed_at,
            rejection_reason=r.rejection_reason,
            issued_key_id=r.issued_key_id,
        ))

    return AdminRequestListResponse(requests=views)


# ── API: approve request (admin) ───────────────────────────────────────────────

@router.post("/api/admin/requests/{request_id}/approve", response_model=RequestApproveResponse)
async def approve_request(
    request_id: int,
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Approve a key request and auto-generate a key for the requesting user."""
    req = db.query(KeyRequest).filter(KeyRequest.id == request_id).first()
    if not req:
        raise HTTPException(status_code=404, detail="Request not found.")
    if req.status != "pending":
        raise HTTPException(status_code=409, detail=f"Request is already {req.status}.")

    # Don't allow admin to approve their own request (shouldn't exist — admins auto-approve)
    if req.user_id == current_user.id:
        raise HTTPException(status_code=403, detail="Cannot approve your own request.")

    # Generate key
    plaintext = generate_enterprise_key()
    key_hash = hash_enterprise_key(plaintext)
    kid = key_id_from_hash(key_hash)
    now = datetime.now(timezone.utc)

    new_key = EnterpriseKey(
        key_hash=key_hash,
        key_id=kid,
        owner_id=req.user_id,
        is_consumed=False,
        is_revoked=False,
        created_at=now,
        expires_at=compute_key_expiry(now),
    )
    db.add(new_key)
    db.commit()
    db.refresh(new_key)

    # Update request — encrypt plaintext key before persisting
    req.status = "approved"
    req.reviewed_by = current_user.id
    req.reviewed_at = now
    req.issued_key_id = new_key.id

    import logging as _log

    from ks.key_crypto import encrypt_pending_key
    try:
        req.pending_display_key = encrypt_pending_key(plaintext)
    except RuntimeError:
        _log.getLogger("ks.admin").warning(
            "LUME_KS_ENCRYPTION_KEY not set — pending_display_key stored as plaintext. "
            "Set this variable before production deployment."
        )
        req.pending_display_key = plaintext

    db.commit()

    req_user = db.query(User).filter(User.id == req.user_id).first()
    write_event(db, "key_approved",
                actor_id=current_user.id, target_user_id=req.user_id,
                key_id=new_key.id, request_id=req.id,
                event_data={"key_id_short": kid, "issued_to": req_user.username if req_user else "unknown"})
    db.commit()

    return RequestApproveResponse(
        request_id=req.id,
        key_id=kid,
        issued_to=req_user.username if req_user else "unknown",
    )


# ── API: reject request (admin) ────────────────────────────────────────────────

@router.post("/api/admin/requests/{request_id}/reject")
async def reject_request(
    request_id: int,
    body: RequestRejectRequest,
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Reject a key request with a reason."""
    req = db.query(KeyRequest).filter(KeyRequest.id == request_id).first()
    if not req:
        raise HTTPException(status_code=404, detail="Request not found.")
    if req.status != "pending":
        raise HTTPException(status_code=409, detail=f"Request is already {req.status}.")
    if req.user_id == current_user.id:
        raise HTTPException(status_code=403, detail="Cannot reject your own request.")

    req.status = "rejected"
    req.reviewed_by = current_user.id
    req.reviewed_at = datetime.now(timezone.utc)
    req.rejection_reason = body.reason
    db.commit()

    write_event(db, "key_rejected",
                actor_id=current_user.id, target_user_id=req.user_id,
                request_id=req.id,
                event_data={"reason": body.reason})
    db.commit()
    return {"request_id": req.id, "status": "rejected", "reason": body.reason}


# ── Browser: approve/reject via form ──────────────────────────────────────────

@router.post("/admin/requests/{request_id}/approve", response_class=HTMLResponse)
async def approve_request_form(
    request_id: int,
    request: Request,
    current_user: User = Depends(require_role_cookie("admin")),
    db: Session = Depends(get_db),
):
    """Browser form: admin approves a request."""
    await approve_request(request_id, current_user, db)
    return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/admin/requests/{request_id}/reject", response_class=HTMLResponse)
async def reject_request_form(
    request_id: int,
    request: Request,
    current_user: User = Depends(require_role_cookie("admin")),
    db: Session = Depends(get_db),
):
    """Browser form: admin rejects a request."""
    req = db.query(KeyRequest).filter(KeyRequest.id == request_id).first()
    if not req:
        raise HTTPException(status_code=404, detail="Request not found.")
    if req.status != "pending":
        raise HTTPException(status_code=409, detail=f"Request is already {req.status}.")
    if req.user_id == current_user.id:
        raise HTTPException(status_code=403, detail="Cannot reject your own request.")

    # Get reason from form data
    form = await request.form()
    reason = form.get("reason", "Rejected by admin")

    req.status = "rejected"
    req.reviewed_by = current_user.id
    req.reviewed_at = datetime.now(timezone.utc)
    req.rejection_reason = reason
    db.commit()

    return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_303_SEE_OTHER)


# ── API: list all users (admin) ────────────────────────────────────────────────

@router.get("/api/admin/users", response_model=AdminUserListResponse)
async def list_users(
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    users = db.query(User).order_by(User.created_at.desc()).all()
    views = []
    for u in users:
        key_count = db.query(EnterpriseKey).filter(EnterpriseKey.owner_id == u.id).count()
        pending_count = db.query(KeyRequest).filter(
            KeyRequest.user_id == u.id, KeyRequest.status == "pending"
        ).count()
        views.append(AdminUserView(
            id=u.id, username=u.username, email=u.email,
            role=u.role, is_active=u.is_active, created_at=u.created_at,
            key_count=key_count, pending_request_count=pending_count,
        ))
    return AdminUserListResponse(users=views)


# ── API: change user role (admin) ──────────────────────────────────────────────

@router.post("/api/admin/users/{user_id}/role")
async def change_user_role(
    user_id: int,
    body: ChangeRoleRequest,
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Change a user's role. Cannot change own role."""
    if user_id == current_user.id:
        raise HTTPException(status_code=403, detail="Cannot change your own role.")

    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found.")

    # If demoting an admin, ensure at least one active admin remains
    if target.role == "admin" and body.role != "admin":
        active_admins = db.query(User).filter(User.role == "admin", User.is_active.is_(True)).count()
        if active_admins <= 1:
            raise HTTPException(
                status_code=409,
                detail="Cannot demote the last active admin. Promote another user first.",
            )

    target.role = body.role
    db.commit()
    write_event(db, "user_role_changed",
                actor_id=current_user.id, target_user_id=user_id,
                event_data={"new_role": body.role, "username": target.username})
    db.commit()
    return {"user_id": user_id, "role": body.role}


# ── Browser: change role via form ─────────────────────────────────────────────

@router.post("/admin/users/{user_id}/role", response_class=HTMLResponse)
async def change_role_form(
    user_id: int,
    request: Request,
    current_user: User = Depends(require_role_cookie("admin")),
    db: Session = Depends(get_db),
):
    if user_id == current_user.id:
        raise HTTPException(status_code=403, detail="Cannot change your own role.")

    form = await request.form()
    new_role = form.get("role", "enterprise_user")

    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found.")

    if target.role == "admin" and new_role != "admin":
        active_admins = db.query(User).filter(User.role == "admin", User.is_active.is_(True)).count()
        if active_admins <= 1:
            raise HTTPException(status_code=409, detail="Cannot demote the last active admin.")

    target.role = new_role
    db.commit()
    return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_303_SEE_OTHER)


# ── API: deactivate user (admin) ───────────────────────────────────────────────

@router.post("/api/admin/users/{user_id}/deactivate")
async def deactivate_user(
    user_id: int,
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Deactivate a user and revoke all their unconsumed keys. Cannot deactivate self."""
    if user_id == current_user.id:
        raise HTTPException(status_code=403, detail="Cannot deactivate your own account.")

    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found.")
    if not target.is_active:
        raise HTTPException(status_code=409, detail="User is already deactivated.")

    # If deactivating an admin, ensure at least one remains
    if target.role == "admin":
        active_admins = db.query(User).filter(User.role == "admin", User.is_active.is_(True)).count()
        if active_admins <= 1:
            raise HTTPException(
                status_code=409,
                detail="Cannot deactivate the last active admin.",
            )

    target.is_active = False
    now = datetime.now(timezone.utc)
    unconsumed = db.query(EnterpriseKey).filter(
        EnterpriseKey.owner_id == user_id,
        EnterpriseKey.is_consumed.is_(False),
        EnterpriseKey.is_revoked.is_(False),
    ).all()
    for k in unconsumed:
        k.is_revoked = True
        k.revoked_at = now
        k.revoked_by = current_user.id
    db.commit()
    write_event(db, "user_deactivated",
                actor_id=current_user.id, target_user_id=user_id,
                event_data={"username": target.username, "revoked_keys": len(unconsumed)})
    db.commit()
    return {"user_id": user_id, "is_active": False, "revoked_keys": len(unconsumed)}


# ── Browser: deactivate via form ───────────────────────────────────────────────

@router.post("/admin/users/{user_id}/deactivate", response_class=HTMLResponse)
async def deactivate_user_form(
    user_id: int,
    current_user: User = Depends(require_role_cookie("admin")),
    db: Session = Depends(get_db),
):
    await deactivate_user(user_id, current_user, db)
    return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_303_SEE_OTHER)


# ── API: activate user (admin) ─────────────────────────────────────────────────

@router.post("/api/admin/users/{user_id}/activate")
async def activate_user(
    user_id: int,
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found.")
    target.is_active = True
    db.commit()
    return {"user_id": user_id, "is_active": True}


@router.post("/admin/users/{user_id}/activate", response_class=HTMLResponse)
async def activate_user_form(
    user_id: int,
    current_user: User = Depends(require_role_cookie("admin")),
    db: Session = Depends(get_db),
):
    await activate_user(user_id, current_user, db)
    return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_303_SEE_OTHER)


# ── Account approval (admin approves new signups) ─────────────────────────────

@router.post("/api/admin/users/{user_id}/approve-account")
async def approve_account(
    user_id: int,
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Approve a user account so they can log in and request keys."""
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found.")
    if target.is_approved:
        raise HTTPException(status_code=409, detail="Account is already approved.")
    target.is_approved = True
    db.commit()
    write_event(db, "account_approved",
                actor_id=current_user.id, target_user_id=user_id,
                event_data={"username": target.username})
    db.commit()
    return {"user_id": user_id, "is_approved": True, "username": target.username}


@router.post("/admin/users/{user_id}/approve-account", response_class=HTMLResponse)
async def approve_account_form(
    user_id: int,
    current_user: User = Depends(require_role_cookie("admin")),
    db: Session = Depends(get_db),
):
    await approve_account(user_id, current_user, db)
    return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/api/admin/users/{user_id}/reject-account")
async def reject_account(
    user_id: int,
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Reject and deactivate a pending account."""
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found.")
    target.is_active = False
    target.is_approved = False
    db.commit()
    write_event(db, "account_rejected",
                actor_id=current_user.id, target_user_id=user_id,
                event_data={"username": target.username})
    db.commit()
    return {"user_id": user_id, "is_active": False, "username": target.username}


@router.post("/admin/users/{user_id}/reject-account", response_class=HTMLResponse)
async def reject_account_form(
    user_id: int,
    current_user: User = Depends(require_role_cookie("admin")),
    db: Session = Depends(get_db),
):
    await reject_account(user_id, current_user, db)
    return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_303_SEE_OTHER)


# ── API: list all keys (admin audit) ───────────────────────────────────────────

@router.get("/api/admin/keys", response_model=AdminKeyListResponse)
async def list_all_keys(
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    keys = db.query(EnterpriseKey).order_by(EnterpriseKey.created_at.desc()).limit(200).all()
    views = []
    for k in keys:
        owner = db.query(User).filter(User.id == k.owner_id).first()
        revoker = db.query(User).filter(User.id == k.revoked_by).first() if k.revoked_by else None
        views.append(AdminKeyView(
            id=k.id, key_id=k.key_id,
            owner_username=owner.username if owner else "unknown",
            is_consumed=k.is_consumed, is_revoked=k.is_revoked,
            created_at=k.created_at, consumed_at=k.consumed_at,
            consumed_by_scan_target=k.consumed_by_scan_target,
            expires_at=k.expires_at, revoked_at=k.revoked_at,
            revoked_by_username=revoker.username if revoker else None,
        ))
    return AdminKeyListResponse(keys=views)


# ── API: revoke key (admin) ────────────────────────────────────────────────────

@router.post("/api/admin/keys/{key_id}/revoke")
async def revoke_key(
    key_id: int,
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Revoke an unconsumed key."""
    key = db.query(EnterpriseKey).filter(EnterpriseKey.id == key_id).first()
    if not key:
        raise HTTPException(status_code=404, detail="Key not found.")
    if key.is_revoked:
        raise HTTPException(status_code=409, detail="Key is already revoked.")
    if key.is_consumed:
        raise HTTPException(status_code=409, detail="Cannot revoke a consumed key.")

    key.is_revoked = True
    key.revoked_at = datetime.now(timezone.utc)
    key.revoked_by = current_user.id
    db.commit()
    write_event(db, "key_revoked",
                actor_id=current_user.id, target_user_id=key.owner_id,
                key_id=key_id,
                event_data={"key_id_short": key.key_id})
    db.commit()
    return {"key_id": key_id, "is_revoked": True}


# ── Browser: revoke key via form ───────────────────────────────────────────────

@router.post("/admin/keys/{key_id}/revoke", response_class=HTMLResponse)
async def revoke_key_form(
    key_id: int,
    current_user: User = Depends(require_role_cookie("admin")),
    db: Session = Depends(get_db),
):
    await revoke_key(key_id, current_user, db)
    return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_303_SEE_OTHER)
