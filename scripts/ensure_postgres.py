"""Create the localai role and the litellm database. Does not print the password."""

from __future__ import annotations

import os
from pathlib import Path

import psycopg
from psycopg import sql


def main() -> None:
    password = os.environ.get("POSTGRES_PASSWORD", "")
    if not password or "\x00" in password:
        raise SystemExit("POSTGRES_PASSWORD is missing")
    schema_path = Path(os.environ.get("AUDIT_SCHEMA", "/opt/local-ai-stack/postgres/init/001-audit.sql"))
    schema = schema_path.read_text(encoding="utf-8")
    admin = "dbname=postgres user=postgres host=/var/run/postgresql"
    with psycopg.connect(admin, autocommit=True) as conn:
        exists = conn.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", ("localai",)).fetchone()
        verb = "ALTER ROLE localai WITH LOGIN PASSWORD {}" if exists else "CREATE ROLE localai LOGIN PASSWORD {}"
        conn.execute(sql.SQL(verb).format(sql.Literal(password)))
        if conn.execute("SELECT 1 FROM pg_database WHERE datname = %s", ("litellm",)).fetchone() is None:
            conn.execute("CREATE DATABASE litellm OWNER localai")
    with psycopg.connect("dbname=litellm user=postgres host=/var/run/postgresql", autocommit=True) as conn:
        for statement in schema.split(";"):
            stmt = statement.strip()
            if stmt:
                conn.execute(stmt)


if __name__ == "__main__":
    main()
