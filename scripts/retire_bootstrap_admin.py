"""Disable the local bootstrap admin after the first Entra admin exists.

Clears the bootstrap password hash and the on-disk password file. Does not
print either secret. Exits 0 while no Entra admin is present, unless --require.
"""

from __future__ import annotations

import argparse
import os
import sqlite3
import stat
import sys
from pathlib import Path

BOOTSTRAP_EMAIL = "webui-bootstrap@local-ai.internal"

FIND_ENTRA_ADMIN = """
SELECT id FROM user
WHERE role = 'admin'
  AND lower(email) != lower(?)
  AND oauth IS NOT NULL
  AND trim(oauth) NOT IN ('null', '{}', '')
"""
DISABLE_USER = "UPDATE user SET role = 'pending' WHERE lower(email) = lower(?)"
CLEAR_PASSWORD = "UPDATE auth SET password = NULL, active = 0 WHERE lower(email) = lower(?)"


def retire(conn: sqlite3.Connection, email: str) -> str:
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    if "user" not in tables:
        return "not-ready"
    admins = conn.execute(FIND_ENTRA_ADMIN, (email,)).fetchall()
    if not admins:
        return "waiting"
    conn.execute(DISABLE_USER, (email,))
    if "auth" in tables:
        conn.execute(CLEAR_PASSWORD, (email,))
    conn.commit()
    return "retired"


def clear_password_file(path: Path) -> None:
    if not path.exists():
        return
    path.write_bytes(b"")
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--password-file", type=Path)
    parser.add_argument("--email", default=BOOTSTRAP_EMAIL)
    parser.add_argument("--require", action="store_true")
    args = parser.parse_args()
    if not args.db.exists():
        print("webui database not ready")
        if args.require:
            raise SystemExit(1)
        return
    with sqlite3.connect(args.db) as conn:
        state = retire(conn, args.email)
    if state == "retired" and args.password_file is not None:
        clear_password_file(args.password_file)
    print(state)
    if args.require and state != "retired":
        raise SystemExit(1)


if __name__ == "__main__":
    sys.exit(main())
