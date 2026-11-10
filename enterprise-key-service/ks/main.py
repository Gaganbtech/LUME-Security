"""FastAPI application factory for the LUME Enterprise Key Service.

Production vs development behaviour is controlled by LUME_KS_ENV:
  LUME_KS_ENV=production  → HTTPS-only cookies, /docs disabled, strict CORS
  LUME_KS_ENV=development → HTTP cookies, /docs enabled (default)
"""

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.middleware.sessions import SessionMiddleware

from ks.config import settings
from ks.database import init_db
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
    limiter = Limiter(key_func=get_remote_address)
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

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
