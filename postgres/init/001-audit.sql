-- Redacted audit events only. Do not add columns for raw prompts.
CREATE TABLE IF NOT EXISTS audit_event (
    id TEXT PRIMARY KEY,
    ts TIMESTAMPTZ NOT NULL,
    user_id TEXT,
    user_email TEXT,
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
);

CREATE INDEX IF NOT EXISTS audit_event_ts_idx ON audit_event (ts);
CREATE INDEX IF NOT EXISTS audit_event_user_idx ON audit_event (user_id);
ALTER TABLE audit_event ADD COLUMN IF NOT EXISTS user_email TEXT;
