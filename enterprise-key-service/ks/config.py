"""Service configuration loaded from environment / .env file."""

import os
from pathlib import Path

from dotenv import load_dotenv

# Load .env from the same directory as this file (the service root),
# regardless of the current working directory.
_ENV_FILE = Path(__file__).parent.parent / ".env"
load_dotenv(dotenv_path=_ENV_FILE)


def _require(key: str) -> str:
    value = os.getenv(key, "").strip()
    if not value:
        raise RuntimeError(
            f"Required environment variable '{key}' is not set. "
            f"Copy .env.example to .env and set a value."
        )
    return value


class Settings:
    # Security
    secret_key: str = ""
    audit_secret: str = ""
    encryption_key: str = ""   # Fernet key for pending_display_key
    algorithm: str = "HS256"
    token_expire_seconds: int = 28800
    is_production: bool = False

    # Database
    db_url: str = "sqlite:///./lume_keys.db"

    # Database connection pool (PostgreSQL only — ignored for SQLite)
    db_pool_size: int = 3         # active connections kept open
    db_max_overflow: int = 7      # extra connections allowed under load
    db_pool_timeout: int = 30     # seconds to wait for a connection
    db_pool_recycle: int = 1800   # recycle connections after 30 minutes

    # CORS
    allowed_origins: list[str] = ["http://localhost:8100"]

    def load(self) -> None:
        self.secret_key = _require("LUME_KS_SECRET_KEY")

        # ── Audit secret ──────────────────────────────────────────────
        # LUME_KS_AUDIT_SECRET must be set independently in production.
        # In development we warn if it is missing; in production we refuse to start.
        raw_audit = os.getenv("LUME_KS_AUDIT_SECRET", "").strip()
        self.is_production = os.getenv("LUME_KS_ENV", "development").lower() == "production"

        if not raw_audit:
            if self.is_production:
                raise RuntimeError(
                    "LUME_KS_AUDIT_SECRET is not set. "
                    "This secret must be distinct from LUME_KS_SECRET_KEY. "
                    "Generate with: python -c \"import secrets; print(secrets.token_hex(32))\""
                )
            # Development fallback with a visible warning — not silent
            import warnings
            warnings.warn(
                "LUME_KS_AUDIT_SECRET is not set. Falling back to LUME_KS_SECRET_KEY for "
                "audit HMAC signing. Set LUME_KS_AUDIT_SECRET before deploying to production.",
                stacklevel=2,
            )
            self.audit_secret = self.secret_key
        else:
            self.audit_secret = raw_audit

        # Reject identical JWT and audit secrets in production — security risk
        if self.is_production and self.audit_secret == self.secret_key:
            raise RuntimeError(
                "LUME_KS_AUDIT_SECRET must be different from LUME_KS_SECRET_KEY. "
                "Using the same value means rotating one secret invalidates the other. "
                "Generate a separate value with: "
                "python -c \"import secrets; print(secrets.token_hex(32))\""
            )

        # Encryption key is optional in development but required in production
        self.encryption_key = os.getenv("LUME_KS_ENCRYPTION_KEY", "")
        self.algorithm = "HS256"
        self.token_expire_seconds = int(os.getenv("LUME_KS_TOKEN_EXPIRE_SECONDS", "28800"))
        self.db_url = os.getenv("LUME_KS_DB_URL", "sqlite:///./lume_keys.db")
        raw_origins = os.getenv("LUME_KS_ALLOWED_ORIGINS", "http://localhost:8100")
        self.allowed_origins = [o.strip() for o in raw_origins.split(",") if o.strip()]

        # ── Database pool settings (tuned for Supabase free tier) ─────
        self.db_pool_size = int(os.getenv("LUME_KS_DB_POOL_SIZE", "3"))
        self.db_max_overflow = int(os.getenv("LUME_KS_DB_MAX_OVERFLOW", "7"))
        self.db_pool_timeout = int(os.getenv("LUME_KS_DB_POOL_TIMEOUT", "30"))
        self.db_pool_recycle = int(os.getenv("LUME_KS_DB_POOL_RECYCLE", "1800"))

        if self.is_production and not self.encryption_key:
            raise RuntimeError(
                "LUME_KS_ENCRYPTION_KEY must be set in production. "
                "Generate one with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
            )


settings = Settings()
