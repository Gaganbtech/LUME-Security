"""SQLAlchemy engine, session factory, and declarative base."""

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from ks.config import settings


class Base(DeclarativeBase):
    pass


# Engine is created lazily when init_db() is called so tests can override
_engine = None
SessionLocal = None


def init_db(db_url: str | None = None) -> None:
    """Initialise the database engine and create all tables.

    For SQLite in-memory databases (used in tests), the URL
    'sqlite:///file::memory:?cache=shared&uri=true' ensures all
    connections share the same in-memory database so that tables created
    by one session are visible to others.
    """
    global _engine, SessionLocal
    url = db_url or settings.db_url

    if url == "sqlite:///:memory:":
        # Shared in-memory DB so all sessions within the same process
        # see the same tables and data.
        url = "sqlite:///file::memory:?cache=shared&uri=true"
        connect_args = {"check_same_thread": False, "uri": True}
    elif url.startswith("sqlite"):
        connect_args = {"check_same_thread": False}
    else:
        connect_args = {}

    # Supabase / PgBouncer transaction pooler:
    # 1. Strip ?pgbouncer=true — it is a Prisma/JS hint not valid for psycopg2
    # 2. Force postgresql+psycopg2:// dialect — prevents SQLAlchemy from
    #    accidentally selecting psycopg v3 which is not installed
    engine_kwargs: dict = {"connect_args": connect_args}
    if "pgbouncer=true" in url.lower():
        url = url.split("?")[0]

    if url.startswith("postgresql://") or url.startswith("postgres://"):
        url = url.replace("postgresql://", "postgresql+psycopg2://", 1)
        url = url.replace("postgres://", "postgresql+psycopg2://", 1)

    _engine = create_engine(url, **engine_kwargs)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=_engine)

    # Import models so Base knows about them before create_all
    import ks.models  # noqa: F401
    # Only drop tables for in-memory test databases; never drop file-based DBs
    if ":memory:" in url or "file::memory:" in url:
        Base.metadata.drop_all(bind=_engine)
    Base.metadata.create_all(bind=_engine)

    # Migrate existing tables: add missing columns for older DB schemas
    _migrate(_engine)


def get_db():
    """FastAPI dependency yielding a database session."""
    if SessionLocal is None:
        raise RuntimeError("Database not initialised. Call init_db() first.")
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _migrate(engine) -> None:
    """Add missing columns to existing tables for schema upgrades.

    SQLite supports ADD COLUMN but not IF NOT EXISTS, so we check the
    existing columns first via PRAGMA table_info.
    """
    from sqlalchemy import inspect, text

    insp = inspect(engine)

    # Users table: add 'role' column if missing
    if "users" in insp.get_table_names():
        cols = {c["name"] for c in insp.get_columns("users")}
        if "role" not in cols:
            with engine.begin() as conn:
                conn.execute(
                    text("ALTER TABLE users ADD COLUMN role VARCHAR(32) DEFAULT 'enterprise_user' NOT NULL")
                )
        # New: account approval column. Existing users (seeded/admins) default to approved.
        if "is_approved" not in cols:
            with engine.begin() as conn:
                conn.execute(
                    text("ALTER TABLE users ADD COLUMN is_approved BOOLEAN DEFAULT 1 NOT NULL")
                )

    # enterprise_keys table: add is_revoked, expires_at, revoked_at, revoked_by
    if "enterprise_keys" in insp.get_table_names():
        cols = {c["name"] for c in insp.get_columns("enterprise_keys")}
        additions = []
        if "is_revoked" not in cols:
            additions.append("ALTER TABLE enterprise_keys ADD COLUMN is_revoked BOOLEAN DEFAULT 0 NOT NULL")
        if "expires_at" not in cols:
            additions.append("ALTER TABLE enterprise_keys ADD COLUMN expires_at DATETIME")
        if "revoked_at" not in cols:
            additions.append("ALTER TABLE enterprise_keys ADD COLUMN revoked_at DATETIME")
        if "revoked_by" not in cols:
            additions.append("ALTER TABLE enterprise_keys ADD COLUMN revoked_by INTEGER")
        for sql in additions:
            with engine.begin() as conn:
                conn.execute(text(sql))

    # Ensure audit_logs table exists (handled by create_all, but explicit migration safety)
    if "audit_logs" not in insp.get_table_names():
        import ks.models  # noqa: F401 — ensure AuditLog is registered
        Base.metadata.create_all(bind=engine)

    # Widen pending_display_key from VARCHAR(128) to VARCHAR(512) for Fernet tokens
    if "key_requests" in insp.get_table_names():
        kr_cols = {c["name"]: c for c in insp.get_columns("key_requests")}
        if "pending_display_key" in kr_cols:
            # SQLite: VARCHAR size is not enforced — no migration needed.
            # PostgreSQL: ALTER COLUMN TYPE is safe if widening.
            # Wrapped in try/except so a permission error never blocks startup.
            dialect = engine.dialect.name
            if dialect == "postgresql":
                try:
                    with engine.begin() as conn:
                        conn.execute(text(
                            "ALTER TABLE key_requests "
                            "ALTER COLUMN pending_display_key TYPE VARCHAR(512)"
                        ))
                except Exception:
                    pass  # Already wide enough, no permission, or unsupported — non-fatal
