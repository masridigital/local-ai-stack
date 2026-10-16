"""Cheap follow-ups from the 2026-10-16 review. Synthetic values only."""

from __future__ import annotations

import http.client
import json
import os
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


def test_azure_uses_api_key_and_gateway_is_uid_gated():
    from scripts.egress_owners import load_destinations

    raw = load_destinations(ROOT / "deploy" / "egress-destinations.yaml")
    names = {item["name"] for item in raw["destinations"]}
    assert "entra-litellm" not in names
    entra = next(item for item in raw["destinations"] if item["name"] == "entra")
    assert entra["users"] == ["openwebui"]
    config = (ROOT / "litellm" / "config.yaml").read_text(encoding="utf-8")
    assert "api_key: os.environ/AZURE_API_KEY" in config
    assert "client_secret" not in config
    assert "AZURE_CLIENT_SECRET" not in config
    unit = (ROOT / "deploy" / "systemd" / "litellm.service").read_text(encoding="utf-8")
    assert "LoadCredential=azure_api_key:/etc/litellm/azure_api_key" in unit
    assert "azure_client_secret" not in unit
    owner = (ROOT / "deploy" / "ufw" / "owner.rules").read_text(encoding="utf-8")
    gate = "-A ufw-before-output -m owner ! --uid-owner openwebui -d 127.0.0.1 -p tcp --dport 8088 -j REJECT"
    assert gate in owner
    assert owner.index(gate) < owner.index("-o lo -j ACCEPT")
    assert "# litellm -> login.microsoftonline.com" not in owner
    assert "--uid-owner litellm -j REJECT" in owner
    timesync = (ROOT / "deploy" / "systemd" / "timesyncd.conf.d" / "local-ai.conf").read_text(encoding="utf-8")
    assert "NTP=ntp.ubuntu.com" in timesync
    assert "time.cloudflare.com" not in (ROOT / "deploy" / "egress-destinations.yaml").read_text(encoding="utf-8")
    risk = (ROOT / "docs" / "residual-risk.md").read_text(encoding="utf-8")
    assert "asserted by Open WebUI after Entra sign-in" in risk
    assert "validates the JWT" in risk
    assert "oid" in risk


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


def test_retire_bootstrap_admin_clears_password_after_entra_admin(tmp_path):
    from scripts.retire_bootstrap_admin import clear_password_file, retire

    db = tmp_path / "webui.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE user (id TEXT, email TEXT, role TEXT, oauth TEXT)")
    conn.execute("CREATE TABLE auth (id TEXT, email TEXT, password TEXT, active INTEGER)")
    conn.execute(
        "INSERT INTO user VALUES ('boot', 'webui-bootstrap@local-ai.internal', 'admin', NULL)"
    )
    conn.execute(
        "INSERT INTO auth VALUES ('boot', 'webui-bootstrap@local-ai.internal', 'hash-fixture', 1)"
    )
    conn.execute(
        "INSERT INTO user VALUES ('entra', 'pilot@example.invalid', 'user', ?)",
        ('{"microsoft":{"sub":"synthetic-oid"}}',),
    )
    conn.commit()
    assert retire(conn, "webui-bootstrap@local-ai.internal") == "waiting"
    assert conn.execute("SELECT password FROM auth WHERE id = 'boot'").fetchone()[0] == "hash-fixture"
    conn.execute("UPDATE user SET role = 'admin' WHERE id = 'entra'")
    conn.commit()
    password = tmp_path / "webui_admin_password"
    password.write_text("bootstrap-fixture", encoding="utf-8")
    password.chmod(0o600)
    assert retire(conn, "webui-bootstrap@local-ai.internal") == "retired"
    clear_password_file(password)
    assert conn.execute("SELECT role FROM user WHERE id = 'boot'").fetchone()[0] == "pending"
    assert conn.execute("SELECT password, active FROM auth WHERE id = 'boot'").fetchone() == (None, 0)
    assert password.read_bytes() == b""
    assert password.stat().st_mode & 0o777 == 0o600
    entra = conn.execute("SELECT role FROM user WHERE id = 'entra'").fetchone()
    assert entra[0] == "admin"
    waiting = subprocess.run(
        [
            "python3",
            str(ROOT / "scripts" / "retire_bootstrap_admin.py"),
            "--db",
            str(db),
            "--require",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert waiting.returncode == 0
    assert "retired" in waiting.stdout


def test_password_login_check_requires_sshd_and_webui_refusal(tmp_path):
    from http.server import BaseHTTPRequestHandler

    class Signin(BaseHTTPRequestHandler):
        code = 403

        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)
            assert b"synthetic@example.invalid" in body
            self.send_response(type(self).code)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, fmt: str, *args) -> None:
            return

    sshd = tmp_path / "sshd.txt"
    sshd.write_text("passwordauthentication no\npermitrootlogin no\n", encoding="utf-8")
    server = ThreadingHTTPServer(("127.0.0.1", 0), Signin)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_address[1]}"
    script = str(ROOT / "deploy" / "check-password-login.sh")
    try:
        refused = subprocess.run(
            ["bash", script, "--sshd-text", str(sshd), "--webui", url],
            check=False,
            capture_output=True,
            text=True,
        )
        assert refused.returncode == 0, refused.stderr
        assert "password login is refused" in refused.stdout
        assert "synthetic-not-a-password" not in refused.stdout
        Signin.code = 200
        allowed = subprocess.run(
            ["bash", script, "--sshd-text", str(sshd), "--webui", url],
            check=False,
            capture_output=True,
            text=True,
        )
        assert allowed.returncode == 1
        assert "password login was not refused" in allowed.stderr
        Signin.code = 400
        invalid = subprocess.run(
            ["bash", script, "--sshd-text", str(sshd), "--webui", url],
            check=False,
            capture_output=True,
            text=True,
        )
        assert invalid.returncode == 1
        assert "password login returned 400, expected 403" in invalid.stderr
    finally:
        server.shutdown()
        server.server_close()
    sshd.write_text("passwordauthentication yes\n", encoding="utf-8")
    opened = subprocess.run(
        ["bash", script, "--sshd-text", str(sshd), "--allow-down"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert opened.returncode == 1
    assert "password login is not refused" in opened.stderr


def test_admin_role_evidence_matches_object_id_and_omits_tokens(tmp_path):
    from scripts.capture_admin_role import build_evidence

    group_id = "11111111-2222-3333-4444-555555555555"
    assignments = {
        "value": [
            {
                "principalDisplayName": "someone-else",
                "principalId": group_id.upper(),
                "principalType": "Group",
                "appRoleId": "role-admin",
                "accessToken": "should-not-leak",
            },
            {
                "principalDisplayName": "local-ai-admins",
                "principalId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                "principalType": "Group",
                "appRoleId": "role-admin",
            },
        ]
    }
    roles = [{"id": "role-admin", "value": "admin"}, {"id": "role-phi", "value": "phi"}]
    evidence = build_evidence(assignments, roles, group_id)
    assert evidence["assigned"] is True
    assert evidence["group"] == "local-ai-admins"
    assert evidence["group_id"] == group_id
    assert evidence["principal_count"] == 1
    dumped = json.dumps(evidence)
    assert "should-not-leak" not in dumped
    assert "principalDisplayName" not in dumped
    display_only = {
        "value": [
            {
                "principalDisplayName": "local-ai-admins",
                "principalType": "Group",
                "appRoleId": "role-admin",
            }
        ]
    }
    assert build_evidence(display_only, roles, group_id)["assigned"] is False
    assignment_path = tmp_path / "assignments.json"
    role_path = tmp_path / "roles.json"
    output = tmp_path / "evidence" / "local-ai-admins-role.json"
    assignment_path.write_text(json.dumps(assignments), encoding="utf-8")
    role_path.write_text(json.dumps(roles), encoding="utf-8")
    captured = subprocess.run(
        [
            "python3",
            str(ROOT / "scripts" / "capture_admin_role.py"),
            "--group-id",
            group_id,
            "--assignments",
            str(assignment_path),
            "--app-roles",
            str(role_path),
            "--output",
            str(output),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert captured.returncode == 0, captured.stderr
    saved = json.loads(output.read_text(encoding="utf-8"))
    assert saved["assigned"] is True
    assert saved["group_id"] == group_id
    assert output.stat().st_mode & 0o777 == 0o600
    named = subprocess.run(
        [
            "python3",
            str(ROOT / "scripts" / "capture_admin_role.py"),
            "--group-id",
            "local-ai-admins",
            "--assignments",
            str(assignment_path),
            "--app-roles",
            str(role_path),
            "--output",
            str(tmp_path / "named.json"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert named.returncode == 2
    assert "object id" in named.stderr
    roles_only = tmp_path / "phi.json"
    roles_only.write_text(json.dumps([{"id": "role-phi", "value": "phi"}]), encoding="utf-8")
    missing = subprocess.run(
        [
            "python3",
            str(ROOT / "scripts" / "capture_admin_role.py"),
            "--group-id",
            group_id,
            "--assignments",
            str(assignment_path),
            "--app-roles",
            str(roles_only),
            "--output",
            str(tmp_path / "missing.json"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert missing.returncode == 1
    assert "not-assigned" in missing.stdout
    checklist = (ROOT / "docs" / "deploy-checklist.md").read_text(encoding="utf-8")
    assert "run the bootstrap-retire job once with `--require`" in checklist
    assert "HTTP 400 does not count" in checklist


def test_gateway_health_check_runs_as_openwebui():
    script = (ROOT / "deploy" / "health-check.sh").read_text(encoding="utf-8")
    assert "runuser -u openwebui -- curl -fsS --max-time 2 http://127.0.0.1:8088/health" in script
    install = (ROOT / "deploy" / "install.sh").read_text(encoding="utf-8")
    assert 'health-check.sh" gateway' in install
    for line in install.splitlines():
        if "4000/health/liveliness" in line:
            assert "runuser" not in line
            assert "curl" in line


def test_open_webui_run_omits_empty_bootstrap_password(tmp_path):
    cred = tmp_path / "cred"
    cred.mkdir()
    (cred / "webui_secret_key").write_text("webui-fixture", encoding="utf-8")
    (cred / "webui_admin_password").write_text("", encoding="utf-8")
    (cred / "microsoft_client_secret").write_text("entra-fixture", encoding="utf-8")
    (cred / "gateway_client_key").write_text("gateway-fixture", encoding="utf-8")
    capture = tmp_path / "capture"
    binary = tmp_path / "open-webui"
    binary.write_text(
        "#!/bin/sh\nprintf '%s' \"${WEBUI_ADMIN_PASSWORD-unset}\" > \"$CAPTURE\"\n",
        encoding="utf-8",
    )
    binary.chmod(0o755)
    env = os.environ.copy()
    env.update(
        {
            "CREDENTIALS_DIRECTORY": str(cred),
            "OPEN_WEBUI_BIN": str(binary),
            "CAPTURE": str(capture),
        }
    )
    proc = subprocess.run(
        ["bash", str(ROOT / "deploy" / "open-webui-run.sh")],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert capture.read_text(encoding="utf-8") == "unset"
    assert "entra-fixture" not in proc.stdout
