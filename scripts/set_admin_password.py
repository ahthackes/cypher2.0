#!/usr/bin/env python3
"""Generates a bcrypt hash of an admin password for the dashboard.

Usage:
    python scripts/set_admin_password.py
    (enter password when prompted)

Then export the printed value before starting the API:
    export CYPHER_ADMIN_PASSWORD_HASH='$2b$12$....'
    export CYPHER_SESSION_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"
"""
import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cypher.api.auth import hash_password  # noqa: E402

if __name__ == "__main__":
    pw = getpass.getpass("New admin password: ")
    confirm = getpass.getpass("Confirm: ")
    if pw != confirm:
        print("Passwords did not match.", file=sys.stderr)
        sys.exit(1)
    print("\nAdd this to your environment before starting the API:\n")
    print(f'export CYPHER_ADMIN_PASSWORD_HASH=\'{hash_password(pw)}\'')
