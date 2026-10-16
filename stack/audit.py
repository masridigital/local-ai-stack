"""Redacted audit log. Rows store entity types and masked text, never raw PHI."""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

from stack.errors import PolicyError
from stack.masking import Recognizer
from stack.phi_scan import contains_raw_phi


class AuditLog:
    def __init__(self, path: Path, recognizers: list[Recognizer], threshold: float):
        self.path = path
        self.recognizers = recognizers
        self.threshold = threshold
        self._init()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_event (
                    id TEXT PRIMARY KEY,
                    ts TEXT NOT NULL,
                    user_id TEXT,
                    event_type TEXT NOT NULL,
                    route TEXT,
                    backend TEXT,
                    model TEXT,
                    decision TEXT NOT NULL,
                    reason TEXT,
                    entity_types TEXT,
                    prompt_redacted TEXT,
                    response_redacted TEXT,
                    config_hash TEXT
                )
                """
            )

    def write(self, **kwargs) -> dict:
        row = sanitize_row(kwargs, self.recognizers, self.threshold)
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO audit_event (
                    id, ts, user_id, event_type, route, backend, model, decision,
                    reason, entity_types, prompt_redacted, response_redacted, config_hash
                ) VALUES (
                    :id, :ts, :user_id, :event_type, :route, :backend, :model, :decision,
                    :reason, :entity_types, :prompt_redacted, :response_redacted, :config_hash
                )
                """,
                row,
            )
        return row

    def rows(self) -> list[dict]:
        with self._connect() as conn:
            return [dict(row) for row in conn.execute("SELECT * FROM audit_event ORDER BY ts")]


def sanitize_row(kwargs: dict, recognizers: list[Recognizer], threshold: float) -> dict:
    entity_types = kwargs.get("entity_types") or []
    row = {
        "id": str(uuid.uuid4()),
        "ts": datetime.now(timezone.utc).isoformat(),
        "user_id": kwargs.get("user_id"),
        "event_type": kwargs["event_type"],
        "route": kwargs.get("route"),
        "backend": kwargs.get("backend"),
        "model": kwargs.get("model"),
        "decision": kwargs["decision"],
        "reason": kwargs.get("reason"),
        "entity_types": ",".join(entity_types),
        "prompt_redacted": kwargs.get("prompt_redacted"),
        "response_redacted": kwargs.get("response_redacted"),
        "config_hash": kwargs.get("config_hash"),
    }
    if contains_raw_phi(json.dumps(row), recognizers, threshold):
        row["prompt_redacted"] = "[suppressed]"
        row["response_redacted"] = "[suppressed]"
        row["decision"] = "suppressed_raw_phi"
        if contains_raw_phi(json.dumps(row), recognizers, threshold):
            raise PolicyError("audit_phi", "refusing to persist raw PHI", status=500)
    return row


class PostgresAudit:
    """Same redacted row contract as AuditLog, stored in Postgres."""

    def __init__(self, dsn: str, recognizers: list[Recognizer], threshold: float):
        self.dsn = dsn
        self.recognizers = recognizers
        self.threshold = threshold

    def write(self, **kwargs) -> dict:
        row = sanitize_row(kwargs, self.recognizers, self.threshold)
        import psycopg

        with psycopg.connect(self.dsn) as conn:
            conn.execute(
                """
                INSERT INTO audit_event (
                    id, ts, user_id, event_type, route, backend, model, decision,
                    reason, entity_types, prompt_redacted, response_redacted, config_hash
                ) VALUES (
                    %(id)s, %(ts)s, %(user_id)s, %(event_type)s, %(route)s, %(backend)s,
                    %(model)s, %(decision)s, %(reason)s, %(entity_types)s,
                    %(prompt_redacted)s, %(response_redacted)s, %(config_hash)s
                )
                """,
                row,
            )
        return row
