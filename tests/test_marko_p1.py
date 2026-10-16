"""Marko P1 and P2 fixes. Synthetic values only; nothing here is a live credential."""

from __future__ import annotations

import http.client
import os
import stat
import subprocess
import threading
from pathlib import Path

import pytest
import yaml

from stack.errors import PolicyError
from stack.policy import load_policy
from stack.server import MAX_CONTENT_LENGTH, Handler, bind_address, checked_content_length
from scripts.scope_virtual_key import request_body

ROOT = Path(__file__).resolve().parents[1]


def test_zdr_attestation_stays_true():
    text = (ROOT / "litellm" / "policy.yaml").read_text(encoding="utf-8")
    assert "anthropic_zdr_confirmed_by_cap: true" in text
    assert "anthropic_zdr_confirmed_by_cap: false" not in text
    assert "2026-10-15" in text
    assert "BAA has ZDR" in text
    policy = load_policy(ROOT / "litellm" / "policy.yaml")
    assert policy.anthropic_zdr_confirmed_by_cap is True
    plan = (ROOT / "PLAN.md").read_text(encoding="utf-8")
    checklist = (ROOT / "docs" / "deploy-checklist.md").read_text(encoding="utf-8")
    assert "2026-10-15" in plan
    assert "2026-10-15" in checklist
    assert "formal document verification" in checklist.lower() or "Formal document verification" in checklist


def test_open_webui_entra_group_and_no_first_admin():
    env = (ROOT / "deploy" / "env" / "open-webui.env").read_text(encoding="utf-8")
    assert "ENABLE_SIGNUP=false" in env
    assert "ENABLE_LOGIN_FORM=false" in env
    assert "DEFAULT_USER_ROLE=pending" in env
    assert "OAUTH_MERGE_ACCOUNTS_BY_EMAIL=false" in env
    assert "OAUTH_CODE_CHALLENGE_METHOD=S256" in env
    assert "OAUTH_ALLOWED_ROLES=phi,non-phi,admin" in env
    assert "OAUTH_ADMIN_ROLES=admin" in env
    assert "WEBUI_ADMIN_EMAIL=webui-bootstrap@local-ai.internal" in env
    assert "WEBUI_ADMIN_PASSWORD" not in env
    assert "zitadel" not in env.lower()
    assert "GLOBAL_LOG_LEVEL=WARNING" in env
    unit = (ROOT / "deploy" / "systemd" / "open-webui.service").read_text(encoding="utf-8")
    assert "LoadCredential=gateway_client_key:" in unit
    assert "LoadCredential=webui_admin_password:" in unit
    assert "litellm_virtual_key" not in unit
    assert "IPAddressDeny=127.0.0.2" in unit
    assert "IPAddressAllow=" not in unit
    doc = (ROOT / "docs" / "entra-sso.md").read_text(encoding="utf-8")
    assert doc.lower().count("zitadel") == 1
    assert "local-ai-users" in doc
    assert "User assignment required" in doc
    assert "Conditional Access" in doc


def test_units_have_no_hostname_allows():
    for path in (ROOT / "deploy" / "systemd").iterdir():
        if not path.is_file():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.startswith("IPAddressAllow="):
                value = line.split("=", 1)[1].strip()
                assert value[:1].isdigit() or value.startswith(":"), path.name
    litellm = (ROOT / "deploy" / "systemd" / "litellm.service").read_text(encoding="utf-8")
    assert "IPAddressAllow=" not in litellm
    assert "api.anthropic.com" not in litellm
    gateway = (ROOT / "deploy" / "systemd" / "policy-gateway.service").read_text(encoding="utf-8")
    assert "IPAddressAllow=127.0.0.2" in gateway
    assert "http://127.0.0.2:4000" in gateway


def test_anthropic_key_and_egress_are_gated():
    install = (ROOT / "deploy" / "install.sh").read_text(encoding="utf-8")
    assert 'ANTHROPIC_BAA_ENABLED:-false}" == "true"' in install
    assert "rm -f /etc/litellm/anthropic_api_key" in install
    assert "--target /var/lib/local-ai-stack" in install
    assert "unset INSTALL_EGRESS" in (ROOT / "host" / "ufw.sh").read_text(encoding="utf-8")
    run = (ROOT / "deploy" / "litellm-run.sh").read_text(encoding="utf-8")
    assert "anthropic_api_key" in run
    assert '== "true"' not in run or "ANTHROPIC_API_KEY" in run


def test_litellm_run_omits_missing_anthropic_key(tmp_path):
    cred = tmp_path / "cred"
    cred.mkdir()
    (cred / "litellm_master_key").write_text("master-fixture", encoding="utf-8")
    (cred / "azure_client_secret").write_text("azure-fixture", encoding="utf-8")
    (cred / "database_url").write_text("postgresql://localai@127.0.0.1/litellm", encoding="utf-8")
    capture = tmp_path / "capture"
    binary = tmp_path / "litellm"
    binary.write_text(
        "#!/bin/sh\nprintf '%s' \"${ANTHROPIC_API_KEY-unset}\" > \"$CAPTURE\"\n",
        encoding="utf-8",
    )
    binary.chmod(0o755)
    env = os.environ.copy()
    env.update(
        {
            "CREDENTIALS_DIRECTORY": str(cred),
            "LITELLM_BIN": str(binary),
            "CAPTURE": str(capture),
            "BIND_HOST": "127.0.0.2",
        }
    )
    proc = subprocess.run(
        ["bash", str(ROOT / "deploy" / "litellm-run.sh")],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    assert capture.read_text(encoding="utf-8") == "unset"
    assert "master-fixture" not in proc.stdout
    assert "azure-fixture" not in proc.stdout
    (cred / "anthropic_api_key").write_text("anthropic-fixture", encoding="utf-8")
    proc = subprocess.run(
        ["bash", str(ROOT / "deploy" / "litellm-run.sh")],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    assert capture.read_text(encoding="utf-8") == "anthropic-fixture"
    assert "anthropic-fixture" not in proc.stdout
    assert "anthropic-fixture" not in proc.stderr


def test_litellm_run_rejects_wildcard_bind(tmp_path):
    env = os.environ.copy()
    env["CREDENTIALS_DIRECTORY"] = str(tmp_path)
    env["BIND_HOST"] = "::"
    proc = subprocess.run(
        ["bash", str(ROOT / "deploy" / "litellm-run.sh")],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 1
    assert "refusing wildcard bind" in proc.stderr


def test_open_webui_run_uses_gateway_key(tmp_path):
    cred = tmp_path / "cred"
    cred.mkdir()
    (cred / "webui_secret_key").write_text("webui-fixture", encoding="utf-8")
    (cred / "webui_admin_password").write_text("admin-fixture", encoding="utf-8")
    (cred / "microsoft_client_secret").write_text("entra-fixture", encoding="utf-8")
    (cred / "gateway_client_key").write_text("gateway-fixture", encoding="utf-8")
    capture = tmp_path / "capture"
    binary = tmp_path / "open-webui"
    binary.write_text(
        "#!/bin/sh\nprintf '%s' \"$OPENAI_API_KEY\" > \"$CAPTURE\"\n",
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
    assert proc.returncode == 0
    assert capture.read_text(encoding="utf-8") == "gateway-fixture"
    assert "gateway-fixture" not in proc.stdout
    assert "admin-fixture" not in proc.stdout
    traced = subprocess.run(
        ["bash", "-x", str(ROOT / "deploy" / "open-webui-run.sh")],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert traced.returncode == 1
    assert "refusing to start with xtrace" in traced.stderr
    assert "gateway-fixture" not in traced.stderr
    assert "admin-fixture" not in traced.stderr


def test_populate_secrets_are_quiet(tmp_path):
    secret = "entra-client-fixture"
    env = os.environ.copy()
    env["HOST_SECRET_ROOT"] = str(tmp_path)
    env["MICROSOFT_CLIENT_SECRET"] = secret
    env["AZURE_CLIENT_SECRET"] = "azure-client-fixture"
    env["LITELLM_VIRTUAL_KEY"] = "virtual-key-fixture"
    proc = subprocess.run(
        ["bash", str(ROOT / "host" / "secrets" / "populate.sh")],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert secret not in proc.stdout
    assert secret not in proc.stderr
    written = tmp_path / "etc" / "open-webui" / "microsoft_client_secret"
    assert written.read_text(encoding="utf-8") == secret
    assert stat.S_IMODE(written.stat().st_mode) == 0o600
    admin = tmp_path / "etc" / "open-webui" / "webui_admin_password"
    gateway = tmp_path / "etc" / "policy-gateway" / "gateway_client_key"
    copy = tmp_path / "etc" / "open-webui" / "gateway_client_key"
    assert admin.stat().st_mode & 0o777 == 0o600
    assert gateway.read_text(encoding="utf-8") == copy.read_text(encoding="utf-8")
    assert not (tmp_path / "etc" / "litellm" / "anthropic_api_key").exists()
    first_admin = admin.read_bytes()
    proc = subprocess.run(
        ["bash", str(ROOT / "host" / "secrets" / "populate.sh")],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    assert admin.read_bytes() == first_admin
    traced = subprocess.run(
        ["bash", "-x", str(ROOT / "host" / "secrets" / "populate.sh")],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert traced.returncode == 1
    assert secret not in traced.stdout
    assert secret not in traced.stderr


def test_luks_self_check():
    proc = subprocess.run(
        ["python3", str(ROOT / "scripts" / "check_luks.py"), "--self-check"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    assert "luks self-check ok" in proc.stdout


def test_virtual_key_scope():
    foundry = request_body(False)
    assert foundry["models"] == ["foundry-gpt"]
    assert "*" not in foundry["models"]
    both = request_body(True)
    assert both["models"] == ["claude-sonnet", "claude-haiku", "claude-opus", "foundry-gpt"]
    names = [
        item["model_name"]
        for item in yaml.safe_load((ROOT / "litellm" / "config.yaml").read_text(encoding="utf-8"))["model_list"]
    ]
    assert names == both["models"]


def test_content_length_and_bind(monkeypatch):
    with pytest.raises(PolicyError) as exc:
        checked_content_length(str(MAX_CONTENT_LENGTH + 1))
    assert exc.value.status == 413
    with pytest.raises(PolicyError) as exc:
        checked_content_length("nope")
    assert exc.value.status == 400
    assert checked_content_length(None) == 0
    from http.server import ThreadingHTTPServer

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.gateway_client_key = "gateway-test-key"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        conn.putrequest("POST", "/v1/chat/completions")
        conn.putheader("Content-Length", str(MAX_CONTENT_LENGTH + 1))
        conn.putheader("Authorization", "Bearer gateway-test-key")
        conn.endheaders()
        response = conn.getresponse()
        assert response.status == 413
        response.read()
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        conn.putrequest("POST", "/v1/chat/completions")
        conn.putheader("Content-Length", "2")
        conn.putheader("Authorization", "Bearer wrong-key")
        conn.endheaders()
        conn.send(b"{}")
        response = conn.getresponse()
        assert response.status == 401
        response.read()
    finally:
        server.shutdown()
        server.server_close()
    for host in ("::", "::0", "0.0.0.0"):
        monkeypatch.setenv("BIND_HOST", host)
        with pytest.raises(SystemExit):
            bind_address()
