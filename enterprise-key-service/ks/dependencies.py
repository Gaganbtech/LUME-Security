"""FastAPI dependency providers with role-based access control."""

from fastapi import Cookie, Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from ks.auth import decode_access_token
from ks.database import get_db
from ks.models import User


def get_current_user(
    access_token: str | None = Cookie(default=None),
    db: Session = Depends(get_db),
) -> User:
    """Extract and verify the user from the HTTP-only JWT cookie.

    Used by authenticated page routes (dashboard, admin dashboard).
    Returns the User ORM object (including role) or raises 401.
    """
    if not access_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated.",
        )
    username = decode_access_token(access_token)
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired or invalid. Please sign in again.",
        )
    user = db.query(User).filter(User.username == username, User.is_active.is_(True)).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or deactivated.",
        )
    return user


def get_current_user_from_bearer(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> User:
    """Extract user from Authorization: Bearer header (JSON API endpoints)."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated.")
    token = authorization[7:]
    username = decode_access_token(token)
    if not username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token.")
    user = db.query(User).filter(User.username == username, User.is_active.is_(True)).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found.")
    return user


def require_role(*allowed_roles: str):
    """Dependency factory that enforces the user's role server-side.

    Usage:
        @router.post("/admin/users", dependencies=[Depends(require_role("admin"))])
        def admin_only(current_user: User = Depends(get_current_user_from_bearer)):
            ...

    Raises 403 Forbidden if the user's role is not in allowed_roles.
    """
    def _check_role(
        current_user: User = Depends(get_current_user_from_bearer),
    ) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required role: {', '.join(allowed_roles)}. Your role: {current_user.role}.",
            )
        return current_user
    return _check_role


def require_role_cookie(*allowed_roles: str):
    """Same as require_role but for cookie-authenticated page routes (not API)."""
    def _check_role(
        current_user: User = Depends(get_current_user),
    ) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required role: {', '.join(allowed_roles)}.",
            )
        return current_user
    return _check_role
