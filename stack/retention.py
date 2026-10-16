"""Purge Open WebUI chat rows and uploaded files older than the retention window.

The data directory is ePHI and must live on the LUKS volume. This script does
not print row contents.
"""

from __future__ import annotations

import argparse
import sqlite3
from datetime import datetime, timedelta, timezone


def purge(db_path: str, older_than_days: int, now: datetime | None = None) -> dict[str, int]:
    if older_than_days < 1:
        raise SystemExit("retention must be at least 1 day")
    moment = now or datetime.now(timezone.utc)
    cutoff = (moment - timedelta(days=older_than_days)).isoformat()
    removed = {"chat": 0, "file": 0}
    conn = sqlite3.connect(db_path)
    try:
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "chat" in tables:
            cur = conn.execute("DELETE FROM chat WHERE updated_at < ?", (cutoff,))
            removed["chat"] = cur.rowcount
        if "file" in tables:
            cur = conn.execute("DELETE FROM file WHERE created_at < ?", (cutoff,))
            removed["file"] = cur.rowcount
        conn.commit()
    finally:
        conn.close()
    return removed


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", required=True)
    parser.add_argument("--days", type=int, required=True)
    args = parser.parse_args()
    result = purge(args.db, args.days)
    print(f"purged chat={result['chat']} file={result['file']}")


if __name__ == "__main__":
    main()
