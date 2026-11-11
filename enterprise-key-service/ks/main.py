"""FastAPI application factory for the LUME Enterprise Key Service.

Production vs development behaviour is controlled by LUME_KS_ENV:
  LUME_KS_ENV=production  → HTTPS-only cookies, /docs disabled, strict CORS, security headers
  LUME_KS_ENV=development → HTTP cookies, /docs enabled (default)
"""

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import Response

from ks.config import settings
from ks.database import init_db
from ks.rate_limit import limiter
from ks.routes.auth import router as auth_router
from ks.routes.keys import router as keys_router

# ── Load settings at module level ────────────────────────────────────────────
settings.load()

_TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    # Apply PostgreSQL-level audit WORM policy (idempotent, no-op on SQLite)
    import ks.database as _db
    from ks.audit_worm import apply_audit_worm_policy
    if _db._engine is not None:
        apply_audit_worm_policy(_db._engine)
    yield


# ══════════════════════════════════════════════════════════════════════════════
# SECURITY MIDDLEWARE
# ══════════════════════════════════════════════════════════════════════════════

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Inject HTTP security headers on every response.

    CSP allows Google Fonts (used by base.html templates) and inline styles
    (templates use style= attributes extensively). No inline scripts are used
    anywhere in the templates, so script-src is restricted to 'self' only.
    """

    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        is_prod = settings.is_production

        # Content-Security-Policy — allows inline styles (templates use them),
        # Google Fonts CDN, and self-served resources. No inline scripts.
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com data:; "
            "img-src 'self' data:; "
            "script-src 'self' 'unsafe-inline'; "
            "connect-src 'self'; "
            f"frame-ancestors {'none' if is_prod else 'self'}; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY" if is_prod else "SAMEORIGIN"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        if is_prod:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )
        return response


class CSRFMiddleware(BaseHTTPMiddleware):
    """CSRF protection for cookie-authenticated browser requests.

    Strategy: validate the Origin header for state-changing methods
    (POST, PUT, PATCH, DELETE) when the request is authenticated via
    cookie (not via Bearer token).

    Bearer-token API requests (Authorization: Bearer ...) are exempt —
    CSRF does not apply to bearer-token auth because the token is not
    automatically sent by the browser.

    The CLI's POST /keys/validate endpoint is also exempt because:
    1. It does not use cookie auth (no session cookie sent by httpx)
    2. It sends the key in the JSON body, not a cookie
    3. The CLI is not a browser and cannot be CSRF-attacked

    This middleware does NOT interfere with:
    - API routes using Authorization: Bearer header
    - GET requests (read-only, no state change)
    - The CLI integration (no cookies involved)
    """

    SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
    # Endpoints that accept unauthenticated POSTs without cookies
    UNAUTHENTICATED_POST_PATHS = frozenset({
        "/keys/validate",    # CLI key validation — JSON body, no cookie
        "/auth/login",       # JSON API login — returns token, no cookie sent
    })

    async def dispatch(self, request: Request, call_next):
        method = request.method.upper()

        # Only check state-changing methods
        if method in self.SAFE_METHODS:
            return await call_next(request)

        # Check if this is a Bearer-token API request
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            # Bearer token auth — not vulnerable to CSRF
            return await call_next(request)

        # Check if this is an unauthenticated endpoint that doesn't use cookies
        if request.url.path in self.UNAUTHENTICATED_POST_PATHS:
            # Also check: is there an access_token cookie? If not, no CSRF risk.
            cookie = request.cookies.get("access_token")
            if not cookie:
                return await call_next(request)

        # For all other state-changing requests (cookie-authenticated browser forms),
        # validate the Origin header against allowed origins.
        origin = request.headers.get("origin", "")
        referer = request.headers.get("referer", "")

        # Build the list of allowed origins from settings
        allowed = set(settings.allowed_origins)

        # In development, also allow localhost variants
        if not settings.is_production:
            allowed.update({
                "http://localhost:8100",
                "http://127.0.0.1:8100",
                "http://localhost:3000",
                "http://127.0.0.1:3000",
            })

        # Check Origin first (preferred per OWASP)
        if origin:
            if origin in allowed:
                return await call_next(request)
            # Origin present but not allowed → block
            return Response(
                content='{"detail": "CSRF check failed: origin not allowed."}',
                status_code=403,
                media_type="application/json",
                headers={"X-Content-Type-Options": "nosniff"},
            )

        # Fall back to Referer if Origin is absent (some browsers omit Origin on same-origin)
        if referer:
            # Extract the origin portion of the Referer URL
            from urllib.parse import urlparse
            ref_origin = f"{urlparse(referer).scheme}://{urlparse(referer).netloc}"
            if ref_origin in allowed:
                return await call_next(request)
            return Response(
                content='{"detail": "CSRF check failed: referer not allowed."}',
                status_code=403,
                media_type="application/json",
                headers={"X-Content-Type-Options": "nosniff"},
            )

        # No Origin and no Referer on a state-changing cookie-authenticated request
        # This is suspicious — block it.
        # Exception: allow requests with no cookies at all (truly unauthenticated)
        cookie = request.cookies.get("access_token")
        if not cookie and not request.cookies.get("lume_session"):
            # No cookies → not a browser session → allow
            return await call_next(request)

        return Response(
            content='{"detail": "CSRF check failed: missing origin and referer headers."}',
            status_code=403,
            media_type="application/json",
            headers={"X-Content-Type-Options": "nosniff"},
        )


# ══════════════════════════════════════════════════════════════════════════════
# APPLICATION FACTORY
# ══════════════════════════════════════════════════════════════════════════════

def create_app() -> FastAPI:
    is_prod = settings.is_production

    app = FastAPI(
        title="TravLume Enterprise Key Portal",
        description="One-time cryptographic keys for authorised LUME security scans.",
        version="0.2.0",
        lifespan=lifespan,
        # Disable interactive docs in production — exposes API structure
        docs_url=None if is_prod else "/docs",
        redoc_url=None,
        openapi_url=None if is_prod else "/openapi.json",
    )

    # Rate limiting
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    # Security headers (applied first — outermost middleware runs last)
    app.add_middleware(SecurityHeadersMiddleware)

    # CSRF protection for cookie-authenticated state-changing requests
    app.add_middleware(CSRFMiddleware)

    # Session middleware
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.secret_key,
        session_cookie="lume_session",
        same_site="strict",
        https_only=is_prod,       # ← True in production, False in dev
        max_age=settings.token_expire_seconds,
    )

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type"],
    )

    # Routers
    app.include_router(auth_router)
    app.include_router(keys_router)
    from ks.routes.admin import router as admin_router
    app.include_router(admin_router)
    from ks.routes.audit import router as audit_router
    app.include_router(audit_router)

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    async def root(request: Request):
        return _TEMPLATES.TemplateResponse(request=request, name="index.html", context={})

    return app


app = create_app()
