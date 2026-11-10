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

    # CORS
    allowed_origins: list[str] = ["http://localhost:8100"]

    def load(self) -> None:
        self.secret_key = _require("LUME_KS_SECRET_KEY")
        self.audit_secret = os.getenv("LUME_KS_AUDIT_SECRET", self.secret_key)
        # Encryption key is optional in development but required in production
        self.encryption_key = os.getenv("LUME_KS_ENCRYPTION_KEY", "")
        self.algorithm = "HS256"
        self.token_expire_seconds = int(os.getenv("LUME_KS_TOKEN_EXPIRE_SECONDS", "28800"))
        self.db_url = os.getenv("LUME_KS_DB_URL", "sqlite:///./lume_keys.db")
        raw_origins = os.getenv("LUME_KS_ALLOWED_ORIGINS", "http://localhost:8100")
        self.allowed_origins = [o.strip() for o in raw_origins.split(",") if o.strip()]
        self.is_production = os.getenv("LUME_KS_ENV", "development").lower() == "production"
        # In production, encryption key is mandatory
        if self.is_production and not self.encryption_key:
            raise RuntimeError(
                "LUME_KS_ENCRYPTION_KEY must be set in production. "
                "Generate one with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
            )


settings = Settings()
