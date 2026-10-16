"""Purge Open WebUI rows that hold chat text once they pass the retention window.

Open WebUI stores timestamps as integers. chat, chat_message, file, feedback,
shared_chat, and memory use epoch seconds. message and note use epoch
nanoseconds. Comparing those columns to an ISO string keeps expired rows.
"""

from __future__ import annotations

import argparse
import sqlite3
from datetime import datetime, timedelta, timezone

# (table, time column, unit). Only tables whose rows can hold chat text.
CHAT_TEXT_TABLES: tuple[tuple[str, str, str], ...] = (
    ("chat", "updated_at", "s"),
    ("chat_message", "updated_at", "s"),
    ("file", "created_at", "s"),
    ("feedback", "updated_at", "s"),
    ("shared_chat", "updated_at", "s"),
    ("memory", "updated_at", "s"),
    ("message", "updated_at", "ns"),
    ("note", "updated_at", "ns"),
)


def cutoff_value(unit: str, moment: datetime, older_than_days: int) -> int:
    if unit not in {"s", "ns"}:
        raise ValueError(f"unknown timestamp unit {unit}")
    instant = moment - timedelta(days=older_than_days)
    seconds = int(instant.timestamp())
    if unit == "ns":
        return seconds * 1_000_000_000
    return seconds


def purge(db_path: str, older_than_days: int, now: datetime | None = None) -> dict[str, int]:
    if older_than_days < 1:
        raise SystemExit("retention must be at least 1 day")
    moment = now or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    removed = {name: 0 for name, _column, _unit in CHAT_TEXT_TABLES}
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("PRAGMA secure_delete = ON")
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        columns = {
            table: {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
            for table in tables
        }
        for name, column, unit in CHAT_TEXT_TABLES:
            if name not in tables or column not in columns.get(name, set()):
                continue
            cutoff = cutoff_value(unit, moment, older_than_days)
            # Names come from CHAT_TEXT_TABLES and are checked against sqlite_master.
            statement = (
                f"DELETE FROM {name} WHERE typeof({column}) = 'integer' AND {column} < ?"  # nosec B608
            )
            cur = conn.execute(statement, (cutoff,))
            removed[name] = cur.rowcount
        conn.commit()
        conn.execute("VACUUM")
    finally:
        conn.close()
    return removed


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", required=True)
    parser.add_argument("--days", type=int, required=True)
    args = parser.parse_args()
    result = purge(args.db, args.days)
    summary = " ".join(f"{name}={count}" for name, count in result.items())
    print(f"purged {summary}")


if __name__ == "__main__":
    main()
