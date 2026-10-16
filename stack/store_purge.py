"""Purge old audit rows and LiteLLM spend logs.

audit_event is the compliance record and is kept for six years (2190 days),
then deleted. LiteLLM spend logs do not store prompts; they are kept 90 days.
Both tables live in Postgres on the LUKS volume.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path

AUDIT_RETENTION_DAYS = 2190
SPEND_RETENTION_DAYS = 90

# Statements are fixed. Callers cannot choose a table or column.
STATEMENTS = {
    ("audit_event", "?"): 'DELETE FROM "audit_event" WHERE "ts" < ?',
    ("audit_event", "%s"): 'DELETE FROM "audit_event" WHERE "ts" < %s',
    ("LiteLLM_SpendLogs", "?"): 'DELETE FROM "LiteLLM_SpendLogs" WHERE "startTime" < ?',
    ("LiteLLM_SpendLogs", "%s"): 'DELETE FROM "LiteLLM_SpendLogs" WHERE "startTime" < %s',
}


def cutoff(moment: datetime, older_than_days: int) -> str:
    if older_than_days < 1:
        raise SystemExit("retention must be at least 1 day")
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    instant = moment.astimezone(timezone.utc) - timedelta(days=older_than_days)
    return instant.isoformat()


def purge_table(conn, table: str, older_than_days: int, now: datetime | None = None, placeholder: str = "?") -> int:
    statement = STATEMENTS.get((table, placeholder))
    if statement is None:
        raise ValueError(f"refusing to purge {table}")
    moment = now or datetime.now(timezone.utc)
    cur = conn.execute(statement, (cutoff(moment, older_than_days),))
    conn.commit()
    return int(cur.rowcount)


def purge_dsn(path: Path, table: str, older_than_days: int, now: datetime | None = None) -> int:
    dsn = path.read_text(encoding="utf-8").strip()
    if not dsn:
        raise SystemExit(f"{path} is empty")
    import psycopg

    with psycopg.connect(dsn) as conn:
        return purge_table(conn, table, older_than_days, now=now, placeholder="%s")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--audit-dsn-file", type=Path, required=True)
    parser.add_argument("--spend-dsn-file", type=Path, required=True)
    args = parser.parse_args()
    audit_removed = purge_dsn(args.audit_dsn_file, "audit_event", AUDIT_RETENTION_DAYS)
    spend_removed = purge_dsn(args.spend_dsn_file, "LiteLLM_SpendLogs", SPEND_RETENTION_DAYS)
    print(f"purged audit_event={audit_removed} LiteLLM_SpendLogs={spend_removed}")


if __name__ == "__main__":
    main()
