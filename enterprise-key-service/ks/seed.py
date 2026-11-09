"""Local development account seed utility.

Usage:
    python -m ks.seed --username alice --email alice@local.dev
    python -m ks.seed --username alice --email alice@local.dev --generate-password

This script is for LOCAL DEVELOPMENT ONLY. Do not use it in any deployed environment.
It does NOT accept or store predictable passwords; it either prompts interactively
or generates a cryptographically secure temporary password.
"""

import argparse
import getpass
import secrets
import string
import sys

from dotenv import load_dotenv

load_dotenv()


def _generate_password(length: int = 20) -> str:
    """Generate a cryptographically secure random password."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed a local dev account for LUME Key Service")
    parser.add_argument("--username", required=True, help="Username for the new account")
    parser.add_argument("--email", required=True, help="Email for the new account")
    parser.add_argument(
        "--role",
        choices=["admin", "enterprise_user"],
        default="enterprise_user",
        help="Role for the new account (default: enterprise_user)",
    )
    parser.add_argument(
        "--generate-password",
        action="store_true",
        help="Generate a secure random password and print it once (instead of prompting)",
    )
    args = parser.parse_args()

    # Import here so database isn't initialised on module import
    import ks.database as _ksdb
    from ks.auth import hash_password
    from ks.config import settings
    from ks.models import User

    settings.load()
    _ksdb.init_db()

    if args.generate_password:
        plaintext = _generate_password()
        print(f"\n[LUME Key Service] Generated password for '{args.username}': {plaintext}")
        print("Store this password securely — it will NOT be shown again.\n")
    else:
        plaintext = getpass.getpass(f"Password for '{args.username}' (min 12 chars): ")
        if len(plaintext) < 12:
            print("Error: password must be at least 12 characters.", file=sys.stderr)
            sys.exit(1)
        confirm = getpass.getpass("Confirm password: ")
        if plaintext != confirm:
            print("Error: passwords do not match.", file=sys.stderr)
            sys.exit(1)

    if _ksdb.SessionLocal is None:
        print("Error: database not initialised.", file=sys.stderr)
        sys.exit(1)

    db = _ksdb.SessionLocal()
    try:
        existing = db.query(User).filter(User.username == args.username).first()
        if existing:
            print(f"Error: username '{args.username}' already exists.", file=sys.stderr)
            sys.exit(1)

        user = User(
            username=args.username,
            email=args.email,
            hashed_password=hash_password(plaintext),
            is_active=True,
            is_approved=True,   # seeded accounts are pre-approved
            role=args.role,
        )
        db.add(user)
        db.commit()
        print(f"[OK] Created account '{args.username}' ({args.email}).")
    finally:
        db.close()


if __name__ == "__main__":
    main()
