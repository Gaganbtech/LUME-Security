"""Authentication routes: sign-in form (browser) and JSON login (API).

Updated: role-aware redirect (admins → /admin/dashboard, users → /dashboard).
"""

from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from ks.audit import write_event
from ks.auth import create_access_token, hash_password, verify_password
from ks.config import settings
from ks.database import get_db
from ks.models import User
from ks.rate_limit import limiter
from ks.schemas import LoginRequest, TokenResponse

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))

_COOKIE_NAME = "access_token"
_COOKIE_MAX_AGE = settings.token_expire_seconds


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={"error": None},
    )


@router.post("/login", response_class=HTMLResponse)
@limiter.limit("10/minute")
async def login_form(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.username == username, User.is_active.is_(True)).first()
    if not user or not verify_password(password, user.hashed_password):
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"error": "Invalid username or password."},
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    # Block unapproved users with a clear message
    if not user.is_approved:
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"error": "Your account is pending admin approval. You will be able to sign in once an admin has reviewed your account."},
            status_code=status.HTTP_403_FORBIDDEN,
        )
    token = create_access_token(subject=user.username)

    # Redirect admins to admin dashboard, regular users to user dashboard
    redirect_url = "/admin/dashboard" if user.role == "admin" else "/dashboard"

    response = RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        key=_COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="strict",
        max_age=_COOKIE_MAX_AGE,
        secure=settings.is_production,   # HTTPS-only in production
    )
    return response


@router.get("/logout")
async def logout():
    response = RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(key=_COOKIE_NAME)
    return response


# ── Signup ────────────────────────────────────────────────────────────────────

@router.get("/signup", response_class=HTMLResponse)
async def signup_page(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="signup.html",
        context={"error": None, "success": None},
    )


@router.post("/signup", response_class=HTMLResponse)
@limiter.limit("5/minute")
async def signup_form(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    db: Session = Depends(get_db),
):
    # Validation
    if password != confirm_password:
        return templates.TemplateResponse(
            request=request,
            name="signup.html",
            context={"error": "Passwords do not match.", "success": None},
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    if len(password) < 12:
        return templates.TemplateResponse(
            request=request,
            name="signup.html",
            context={"error": "Password must be at least 12 characters.", "success": None},
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    if len(username) < 3:
        return templates.TemplateResponse(
            request=request,
            name="signup.html",
            context={"error": "Username must be at least 3 characters.", "success": None},
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    # Check uniqueness
    if db.query(User).filter(User.username == username).first():
        return templates.TemplateResponse(
            request=request,
            name="signup.html",
            context={"error": "Username is already taken.", "success": None},
            status_code=status.HTTP_409_CONFLICT,
        )
    if db.query(User).filter(User.email == email).first():
        return templates.TemplateResponse(
            request=request,
            name="signup.html",
            context={"error": "An account with this email already exists.", "success": None},
            status_code=status.HTTP_409_CONFLICT,
        )

    # Create user — starts unapproved. Admin must approve before they can request keys.
    new_user = User(
        username=username,
        email=email,
        hashed_password=hash_password(password),
        is_active=True,
        is_approved=False,   # requires admin approval
        role="enterprise_user",
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    write_event(db, "account_signup",
                actor_id=new_user.id, target_user_id=new_user.id,
                event_data={"username": username, "email": email})
    db.commit()

    return templates.TemplateResponse(
        request=request,
        name="signup.html",
        context={
            "error": None,
            "success": "Account created! An admin will review and approve it. You'll be able to sign in and request keys once approved.",
        },
    )


@router.post("/auth/login", response_model=TokenResponse)
@limiter.limit("10/minute")
async def api_login(
    request: Request,
    body: LoginRequest,
    db: Session = Depends(get_db),
):
    """Returns a JWT bearer token with role information."""
    user = db.query(User).filter(User.username == body.username, User.is_active.is_(True)).first()
    if not user or not verify_password(body.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials.")
    if not user.is_approved:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account pending admin approval.")
    token = create_access_token(subject=user.username)
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=settings.token_expire_seconds,
        role=user.role,
    )
