"""Cheap follow-ups from the 2026-10-16 review. Synthetic values only."""

from __future__ import annotations

import http.client
import json
import sqlite3
import subprocess
import threading
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from stack.audit import AuditLog
from stack.masking import load_recognizers
from stack.policy import load_policy
from stack.server import Handler
from stack.store_purge import AUDIT_RETENTION_DAYS, SPEND_RETENTION_DAYS, purge_table

ROOT = Path(__file__).resolve().parents[1]
MARKER = "SYNTHETIC-MARKER-not-phi"


def test_caddy_security_headers_and_caddy_fingerprint():
    caddy = (ROOT / "deploy" / "Caddyfile").read_text(encoding="utf-8")
    assert 'Strict-Transport-Security "max-age=31536000; includeSubDomains"' in caddy
    assert 'X-Content-Type-Options "nosniff"' in caddy
    assert "frame-ancestors 'none'" in caddy
    apt = (ROOT / "deploy" / "apt-repos.sh").read_text(encoding="utf-8")
    assert "65760C51EDEA2017CEA2CA15155B6D79CA56EA34" in apt
    assert "caddy apt key fingerprint mismatch" in apt
    assert "caddy-key.sh" in apt
    assert "pkg.cloudflare.com" not in apt


def test_caddy_key_requires_exactly_one_primary():
    script = ROOT / "deploy" / "caddy-key.sh"
    primary = "65760C51EDEA2017CEA2CA15155B6D79CA56EA34"
    subkey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    def run(dump: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(script)],
            input=dump,
            text=True,
            capture_output=True,
            check=False,
        )

    good = "\n".join(
        [
            "pub:-:4096:1:ABCDEF:1:::-:::scESC::::::23::0:",
            f"fpr:::::::::{primary}:",
            "uid:-::::1::ABCDEF::Caddy:",
            "sub:-:4096:1:SUBKEY:1::::::s::::::23:",
            f"fpr:::::::::{subkey}:",
            "",
        ]
    )
    accepted = run(good)
    assert accepted.returncode == 0, accepted.stderr
    assert accepted.stdout.strip() == primary

    two_primaries = "\n".join(
        [
            "pub:-:4096:1:ONE:1:::::::",
            f"fpr:::::::::{primary}:",
            "pub:-:4096:1:TWO:1:::::::",
            f"fpr:::::::::{subkey}:",
            "",
        ]
    )
    rejected = run(two_primaries)
    assert rejected.returncode != 0
    assert "exactly one primary key" in rejected.stderr

    fingerprint_after_uid = "\n".join(
        [
            "pub:-:4096:1:ONE:1:::::::",
            "uid:-::::1::ABCDEF::Caddy:",
            f"fpr:::::::::{primary}:",
            "",
        ]
    )
    delayed = run(fingerprint_after_uid)
    assert delayed.returncode != 0
    assert "exactly one primary key" in delayed.stderr


def test_litellm_entra_token_host_is_not_shared_with_openwebui():
    from scripts.egress_owners import load_destinations

    raw = load_destinations(ROOT / "deploy" / "egress-destinations.yaml")
    by_name = {item["name"]: item for item in raw["destinations"]}
    litellm = by_name["entra-litellm"]
    assert litellm["users"] == ["litellm"]
    assert litellm["hosts"] == ["login.microsoftonline.com"]
    assert "litellm" not in by_name["entra"]["users"]
    assert "login.microsoft.com" not in litellm["hosts"]
    owner = (ROOT / "deploy" / "ufw" / "owner.rules").read_text(encoding="utf-8")
    assert "# litellm -> login.microsoftonline.com:443/tcp" in owner
    assert "--uid-owner litellm -j REJECT" not in owner
    timesync = (ROOT / "deploy" / "timesyncd" / "local-ai.conf").read_text(encoding="utf-8")
    assert "NTP=ntp.ubuntu.com" in timesync
    assert "time.cloudflare.com" not in (ROOT / "deploy" / "egress-destinations.yaml").read_text(encoding="utf-8")


def test_store_purge_drops_old_audit_and_spend_rows():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE audit_event (id TEXT, ts TEXT)")
    conn.execute('CREATE TABLE "LiteLLM_SpendLogs" (request_id TEXT, "startTime" TEXT)')
    fresh = "2026-10-01T00:00:00+00:00"
    now = datetime(2026, 10, 16, tzinfo=timezone.utc)
    conn.execute("INSERT INTO audit_event VALUES ('old', ?)", ("2010-01-01T00:00:00+00:00",))
    conn.execute("INSERT INTO audit_event VALUES ('new', ?)", (fresh,))
    conn.execute('INSERT INTO "LiteLLM_SpendLogs" VALUES (\'old\', ?)', ("2026-01-01T00:00:00+00:00",))
    conn.execute('INSERT INTO "LiteLLM_SpendLogs" VALUES (\'new\', ?)', (fresh,))
    assert purge_table(conn, "audit_event", AUDIT_RETENTION_DAYS, now=now) == 1
    assert purge_table(conn, "LiteLLM_SpendLogs", SPEND_RETENTION_DAYS, now=now) == 1
    assert conn.execute("SELECT id FROM audit_event").fetchall() == [("new",)]
    assert conn.execute('SELECT request_id FROM "LiteLLM_SpendLogs"').fetchall() == [("new",)]
    with pytest.raises(ValueError, match="refusing to purge"):
        purge_table(conn, "chat", 30, now=now)
    unit = (ROOT / "deploy" / "systemd" / "local-ai-store-purge.service").read_text(encoding="utf-8")
    assert "audit_database_url" in unit
    assert "database_url" in unit
    assert "IPAddressDeny=any" in unit
    assert "IPAddressAllow=127.0.0.1" in unit


def test_unhandled_gateway_error_writes_an_audit_row(tmp_path, monkeypatch):
    recognizers = load_recognizers(ROOT / "presidio" / "recognizers")
    policy = load_policy(ROOT / "litellm" / "policy.yaml")
    audit = AuditLog(tmp_path / "audit.db", recognizers, policy.mask_score_threshold)

    def boom(**_kwargs):
        raise RuntimeError(MARKER)

    monkeypatch.setattr("stack.server.handle_chat", boom)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.gateway_client_key = "gateway-test-key"
    server.deps = (None, None, None, audit)
    server.upstream = object()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    try:
        body = b"{}"
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        conn.putrequest("POST", "/v1/chat/completions")
        conn.putheader("Content-Length", str(len(body)))
        conn.putheader("Authorization", "Bearer gateway-test-key")
        conn.putheader("X-OpenWebUI-User-Id", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        conn.endheaders()
        conn.send(body)
        response = conn.getresponse()
        payload = response.read().decode("utf-8")
        assert response.status == 500
    finally:
        server.shutdown()
        server.server_close()
    assert MARKER not in payload
    parsed = json.loads(payload)
    assert parsed["error"]["code"] == "unhandled"
    assert parsed["error"]["message"] == "request failed"
    rows = audit.rows()
    assert len(rows) == 1
    assert rows[0]["decision"] == "block"
    assert rows[0]["reason"] == "unhandled"
    assert rows[0]["route"] == "/v1/chat/completions"
    assert MARKER not in json.dumps(rows[0])
