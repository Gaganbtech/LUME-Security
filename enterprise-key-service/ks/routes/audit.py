"""Audit log routes — read-only for admins.

POST/PUT/DELETE on audit_logs is never exposed.
"""

from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from ks.audit import verify_chain
from ks.database import get_db
from ks.dependencies import require_role, require_role_cookie
from ks.models import AuditLog, User

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))


@router.get("/api/admin/audit")
async def list_audit_log(
    page: int = 1,
    per_page: int = 50,
    event_type: str | None = None,
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Paginated audit log — admin only."""
    query = db.query(AuditLog).order_by(AuditLog.id.desc())
    if event_type:
        query = query.filter(AuditLog.event_type == event_type)
    total = query.count()
    entries = query.offset((page - 1) * per_page).limit(per_page).all()

    # Resolve actor/target usernames
    user_cache: dict[int, str] = {}

    def _username(uid: int | None) -> str | None:
        if uid is None:
            return None
        if uid not in user_cache:
            u = db.query(User).filter(User.id == uid).first()
            user_cache[uid] = u.username if u else f"user#{uid}"
        return user_cache[uid]

    rows = []
    for e in entries:
        rows.append({
            "id": e.id,
            "event_type": e.event_type,
            "actor": _username(e.actor_id),
            "target_user": _username(e.target_user_id),
            "key_id": e.key_id,
            "request_id": e.request_id,
            "event_data": e.event_data,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
        })

    return {"total": total, "page": page, "per_page": per_page, "entries": rows}


@router.get("/api/admin/audit/verify")
async def verify_audit_chain(
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Walk the full audit chain and verify all HMACs and chain links."""
    result = verify_chain(db)
    return result


@router.get("/admin/audit/verify")
async def verify_audit_chain_browser(
    current_user: User = Depends(require_role_cookie("admin")),
    db: Session = Depends(get_db),
):
    """Same as above but accepts the HTTP-only session cookie from the browser.

    Used by the Verify Chain Integrity button in the audit log template.
    JavaScript cannot read HttpOnly cookies, so the fetch uses
    credentials:'include' to send the cookie automatically, and this
    cookie-authenticated endpoint accepts it.
    """
    result = verify_chain(db)
    return result


@router.get("/api/admin/audit/worm-status")
async def audit_worm_status(
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Return the database-level WORM policy status for the audit_logs table.

    Reports whether PostgreSQL RLS is enabled and forced.
    Returns a note for SQLite (RLS not supported).
    """
    import ks.database as _db
    from ks.audit_worm import verify_audit_worm_policy
    if _db._engine is None:
        return {"error": "Database not initialised"}
    status = verify_audit_worm_policy(_db._engine)
    status["note"] = (
        "PostgreSQL RLS enabled and forced — UPDATE/DELETE blocked at DB level."
        if status.get("rls_forced") else
        "SQLite: application-level append-only restriction active. "
        "No DB-level WORM on SQLite."
        if status.get("dialect") != "postgresql" else
        "RLS not fully applied. Run apply_audit_worm_policy() or check Supabase permissions."
    )
    return status


@router.get("/admin/audit", response_class=HTMLResponse)
async def audit_page(
    request: Request,
    current_user: User = Depends(require_role_cookie("admin")),
    db: Session = Depends(get_db),
):
    """Admin audit log dashboard page."""
    entries = (
        db.query(AuditLog)
        .order_by(AuditLog.id.desc())
        .limit(200)
        .all()
    )

    user_cache: dict[int, str] = {}

    def _username(uid: int | None) -> str | None:
        if uid is None:
            return None
        if uid not in user_cache:
            u = db.query(User).filter(User.id == uid).first()
            user_cache[uid] = u.username if u else f"user#{uid}"
        return user_cache[uid]

    rows = []
    for e in entries:
        rows.append({
            "id": e.id,
            "event_type": e.event_type,
            "actor": _username(e.actor_id) or "system",
            "target_user": _username(e.target_user_id) or "—",
            "key_id": e.key_id,
            "request_id": e.request_id,
            "event_data": e.event_data,
            "timestamp": e.timestamp,
            "chain_ok": True,  # default; full verify is on-demand
        })

    return templates.TemplateResponse(
        request=request,
        name="audit_log.html",
        context={"user": current_user, "entries": rows, "total": len(rows)},
    )
