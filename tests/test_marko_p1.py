"""Marko P1 and P2 fixes. Synthetic values only; nothing here is a live credential."""

from __future__ import annotations

import http.client
import os
import stat
import subprocess
import threading
import time
from pathlib import Path

import pytest
import yaml

from stack.errors import PolicyError
from stack.policy import load_policy
from stack.server import MAX_CONTENT_LENGTH, Handler, bind_address, checked_content_length
from scripts.scope_virtual_key import request_body

ROOT = Path(__file__).resolve().parents[1]


def _sni_extension(names: list[str]) -> bytes:
    entries = b""
    for name in names:
        encoded = name.encode("ascii")
        entries += b"\x00" + len(encoded).to_bytes(2, "big") + encoded
    body = len(entries).to_bytes(2, "big") + entries
    return (0).to_bytes(2, "big") + len(body).to_bytes(2, "big") + body


def _client_hello(
    hostname: str | None,
    *,
    ech: bool = False,
    extra_names: tuple[str, ...] = (),
    duplicate: bool = False,
) -> bytes:
    """Synthetic TLS ClientHello. Not a live handshake."""
    extensions = b""
    names: list[str] = []
    if hostname is not None:
        names.append(hostname)
    names.extend(extra_names)
    if names:
        extensions += _sni_extension(names)
    if duplicate and hostname is not None:
        extensions += _sni_extension([hostname])
    if ech:
        payload = b"\x00\x01"
        extensions += (0xFE0D).to_bytes(2, "big") + len(payload).to_bytes(2, "big") + payload
    body = b"\x03\x03" + (b"\x11" * 32) + b"\x00"
    ciphers = b"\x13\x01"
    body += len(ciphers).to_bytes(2, "big") + ciphers + b"\x01\x00"
    body += len(extensions).to_bytes(2, "big") + extensions
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


def test_zdr_attestation_cites_cap_chat():
    text = (ROOT / "litellm" / "policy.yaml").read_text(encoding="utf-8")
    assert "anthropic_zdr_confirmed_by_cap: true" in text
    assert "anthropic_zdr_confirmed_by_cap: false" not in text
    assert "2026-10-15" in text
    assert "BAA has ZDR" in text
    policy = load_policy(ROOT / "litellm" / "policy.yaml")
    assert policy.anthropic_zdr_confirmed_by_cap is True
    plan = (ROOT / "PLAN.md").read_text(encoding="utf-8")
    checklist = (ROOT / "docs" / "deploy-checklist.md").read_text(encoding="utf-8")
    for blob in (plan, checklist):
        assert "2026-10-15" in blob
        assert "BAA has ZDR" in blob
        assert "8 AM" in blob
    assert "zero data retention" in plan.lower()
    assert "Formal document verification" in checklist


def test_open_webui_entra_group_and_no_first_admin():
    env = (ROOT / "deploy" / "env" / "open-webui.env").read_text(encoding="utf-8")
    assert "ENABLE_SIGNUP=false" in env
    assert "ENABLE_OAUTH_SIGNUP=true" in env
    assert "ENABLE_LOGIN_FORM=false" in env
    assert "ENABLE_PASSWORD_AUTH=false" in env
    assert "DEFAULT_USER_ROLE=pending" in env
    assert "ENABLE_OAUTH_ROLE_MANAGEMENT=true" in env
    assert "ENABLE_OAUTH_GROUP_MANAGEMENT=true" in env
    assert "OAUTH_GROUPS_CLAIM=roles" in env
    assert "OAUTH_MERGE_ACCOUNTS_BY_EMAIL=false" in env
    assert "OAUTH_CODE_CHALLENGE_METHOD=S256" in env
    assert "OAUTH_ALLOWED_ROLES=phi,non-phi,admin" in env
    assert "OAUTH_ADMIN_ROLES=admin" in env
    assert "LOCAL_AI_ADMIN_GROUP=local-ai-admins" in env
    assert "USER_PERMISSIONS_WORKSPACE_TOOLS_ACCESS=false" in env
    assert "USER_PERMISSIONS_WORKSPACE_TOOLS_IMPORT=false" in env
    assert "USER_PERMISSIONS_WORKSPACE_TOOLS_EXPORT=false" in env
    assert "ENABLE_FUNCTIONS=true" in env
    assert "MICROSOFT_CLIENT_TENANT_ID=" in env
    assert "AZURE_TENANT_ID=" not in env
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
    assert "PHI-users" in doc
    assert "local-ai-admins" in doc
    assert "gateway_client_key" in doc
    assert "azure_api_key" in doc
    assert "local-ai-users" not in doc
    assert "Assignment required = Yes" in doc
    assert "Local signup only is off" in doc
    assert "Signup is off" not in doc
    assert "Conditional Access" in doc
    assert "Do not enable public client flows" in doc
    assert "Allow public client flows" not in doc
    assert "{{USER_GROUPS}}" in env
    assert "parse_custom_headers" in doc
    ssh = (ROOT / "host" / "ssh" / "00-local-ai-vpn.conf").read_text(encoding="utf-8")
    assert "AllowTcpForwarding local" in ssh
    assert "PermitOpen 127.0.0.2:4000" in ssh
    assert "PermitTunnel no" in ssh
    assert "AllowStreamLocalForwarding no" in ssh
    other = (ROOT / "deploy" / "ssh" / "99-local-ai.conf").read_text(encoding="utf-8")
    assert "PermitTunnel no" in other
    assert "AllowStreamLocalForwarding no" in other
    assert "AllowTcpForwarding no" not in ssh
    assert "ssh -L 4000:127.0.0.2:4000" in doc


def test_units_have_no_hostname_allows():
    for path in (ROOT / "deploy" / "systemd").iterdir():
        if not path.is_file():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.startswith("IPAddressAllow="):
                value = line.split("=", 1)[1].strip()
                assert value[:1].isdigit() or value.startswith(":"), path.name
    litellm = (ROOT / "deploy" / "systemd" / "litellm.service").read_text(encoding="utf-8")
    assert "IPAddressDeny=any" in litellm
    assert "IPAddressAllow=127.0.0.1" in litellm
    assert "IPAddressAllow=127.0.0.2" in litellm
    assert "http://127.0.0.1:8889" in litellm
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
    (cred / "azure_api_key").write_text("azure-fixture", encoding="utf-8")
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
    env["AZURE_API_KEY"] = "azure-key-fixture"
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
    azure_key = tmp_path / "etc" / "litellm" / "azure_api_key"
    assert azure_key.read_text(encoding="utf-8") == "azure-key-fixture"
    assert stat.S_IMODE(azure_key.stat().st_mode) == 0o600
    assert "azure-key-fixture" not in proc.stdout
    assert not (tmp_path / "etc" / "litellm" / "azure_client_secret").exists()
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


def test_anthropic_dropin_follows_the_switch(tmp_path):
    unit = (ROOT / "deploy" / "systemd" / "litellm.service").read_text(encoding="utf-8")
    assert "LoadCredential=anthropic_api_key" not in unit
    src = ROOT / "deploy" / "systemd" / "litellm.service.d" / "10-anthropic.conf"
    assert "LoadCredential=anthropic_api_key:/etc/litellm/anthropic_api_key" in src.read_text(encoding="utf-8")
    script = ROOT / "deploy" / "litellm-baa-dropin.sh"
    dest = tmp_path / "dropin"
    on = subprocess.run(["bash", str(script), "true", str(dest), str(src)], check=False, capture_output=True, text=True)
    assert on.returncode == 0, on.stderr
    assert (dest / "10-anthropic.conf").is_file()
    off = subprocess.run(["bash", str(script), "false", str(dest), str(src)], check=False, capture_output=True, text=True)
    assert off.returncode == 0, off.stderr
    assert not (dest / "10-anthropic.conf").exists()
    install = (ROOT / "deploy" / "install.sh").read_text(encoding="utf-8")
    stop = install.index("systemctl stop litellm.service")
    delete = install.index("rm -f /etc/litellm/anthropic_api_key")
    dropin = install.index("litellm-baa-dropin.sh")
    # The earlier daemon-reload only restarts the proxy for a re-apply.
    assert install.index("systemctl daemon-reload") < stop
    reload = install.rindex("systemctl daemon-reload")
    start = install.index("systemctl start litellm.service")
    health = install.index("http://127.0.0.2:4000/health/liveliness")
    scope = install.index("scope_virtual_key.py")
    assert stop < delete < dropin < reload < start < health < scope
    assert "systemctl restart litellm.service" not in install
    assert '[[ "$baa_previous" != "$baa_current" ]]' in install
    assert install.index("SCOPE_VIRTUAL_KEY_FORCE=1") < scope
    assert "write-secret.sh\" /etc/cloudflared/credentials.json" not in install
    assert "rm -f /etc/cloudflared/credentials.json" in install


def test_reject_is_spliced_before_loopback_accept():
    from scripts.egress_owners import splice_before_rules

    before = (
        "-A ufw-before-output -o lo -j ACCEPT\n"
        "-A ufw-before-output -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
    )
    block = "-A ufw-before-output -m owner --uid-owner openwebui -d 127.0.0.2 -p tcp --dport 4000 -j REJECT\n"
    once = splice_before_rules(before, block)
    assert once.index("REJECT") < once.index("-o lo -j ACCEPT")
    twice = splice_before_rules(once, block)
    assert twice.index("REJECT") < twice.index("-o lo -j ACCEPT")
    assert twice.count("# BEGIN local-ai-owner") == 1


def test_user_groups_header_stays_comma_separated():
    from string import punctuation
    from urllib.parse import quote

    # Open WebUI 0.12.2 parse_custom_headers joins group names and quotes with punctuation kept.
    value = "{{USER_GROUPS}}".replace("{{USER_GROUPS}}", ",".join(["phi", "non-phi"]))
    encoded = quote(value, safe=punctuation + " \t")
    assert encoded == "phi,non-phi"
    refresh = (ROOT / "deploy" / "egress-refresh.sh").read_text(encoding="utf-8")
    assert "unset INSTALL_EGRESS" in refresh
    timer = (ROOT / "deploy" / "systemd" / "local-ai-egress-refresh.timer").read_text(encoding="utf-8")
    assert "OnUnitActiveSec=5min" in timer
    design = (ROOT / "docs" / "egress-proxy.md").read_text(encoding="utf-8")
    assert "127.0.0.1:8888" in design
    assert "127.0.0.1:8889" in design
    assert "127.0.0.1:8890" in design
    assert "127.0.0.1:8891" in design
    assert "Verify on the VM" in design
    assert "Reboot" in design
    assert "udp sport 68 udp dport 67 accept" in design
    assert "nd-neighbor-solicit" in design
    assert "nobody" in design
    assert "ntp.ubuntu.com" in design
    assert "root blocked" in design
    assert "Host: evil.example" in design
    assert "Wants=network-pre.target" in (ROOT / "deploy" / "systemd" / "local-ai-egress-nft.service").read_text(encoding="utf-8")
    assert "WantedBy=sysinit.target" in (ROOT / "deploy" / "systemd" / "local-ai-egress-nft.service").read_text(encoding="utf-8")
    assert "WantedBy=multi-user.target" in (ROOT / "deploy" / "systemd" / "local-ai-egress-nft.service").read_text(encoding="utf-8")


def test_litellm_port_4000_is_gated():
    """N-3: a direct hit on LiteLLM :4000 is refused unless the virtual key is presented."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    virtual = "virtual-key-fixture"
    gateway = "gateway-key-fixture"

    class Lite(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self._reply(401, b'{"error":"gated"}')

        def do_POST(self):  # noqa: N802
            auth = self.headers.get("Authorization", "")
            if auth == f"Bearer {virtual}":
                self._reply(200, b'{"ok":true}')
                return
            self._reply(401, b'{"error":"gated"}')

        def _reply(self, status: int, body: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt: str, *args) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.2", 4000), Lite)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        def hit(method: str, token: str | None) -> int:
            conn = http.client.HTTPConnection("127.0.0.2", 4000, timeout=2)
            conn.putrequest(method, "/v1/chat/completions")
            body = b"{}"
            conn.putheader("Content-Length", str(len(body)))
            if token:
                conn.putheader("Authorization", f"Bearer {token}")
            conn.endheaders()
            if method == "POST":
                conn.send(body)
            response = conn.getresponse()
            response.read()
            status = response.status
            conn.close()
            return status

        assert hit("GET", None) == 401
        assert hit("POST", gateway) == 401
        assert hit("POST", None) == 401
        assert hit("POST", virtual) == 200
    finally:
        server.shutdown()
        server.server_close()
    env = (ROOT / "deploy" / "env" / "open-webui.env").read_text(encoding="utf-8")
    assert "OPENAI_API_BASE_URL=http://127.0.0.1:8088/v1" in env
    assert ":4000" not in env
    unit = (ROOT / "deploy" / "systemd" / "open-webui.service").read_text(encoding="utf-8")
    assert "IPAddressDeny=127.0.0.2" in unit
    assert "litellm_virtual_key" not in unit


def test_nft_rejects_litellm_before_loopback_accept():
    """N-4: nftables (not UFW text) rejects :4000 before loopback accept, and the proxy list is by name."""
    from stack.egress import host_allowed, load_destinations
    from scripts.egress_nft import render_nft

    if subprocess.run(["id", "openwebui"], check=False, capture_output=True).returncode != 0:
        created = subprocess.run(
            ["sudo", "useradd", "--system", "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", "openwebui"],
            check=False,
            capture_output=True,
            text=True,
        )
        assert created.returncode == 0, created.stderr
    rules = render_nft()
    loopback = rules.index('oifname "lo" accept')
    assert rules.index("ip daddr 127.0.0.2 tcp dport 4000 reject") < loopback
    assert rules.index("ip daddr 127.0.0.1 tcp dport 4000 reject") < loopback
    assert rules.index("tcp dport 8888 meta skuid != openwebui reject") < loopback
    assert rules.index("tcp dport 8889 meta skuid != litellm reject") < loopback
    gateway_gate = 'ip daddr 127.0.0.1 tcp dport 8088 meta skuid != openwebui reject'
    assert rules.index(gateway_gate) < loopback
    assert 'ip daddr 127.0.0.2 tcp dport 8088 meta skuid != openwebui reject' in rules
    assert "meta skuid egress-proxy tcp dport { 80, 443 } accept" in rules
    assert "meta skuid systemd-resolve meta l4proto { tcp, udp } th dport 53 accept" in rules
    assert "meta skuid systemd-timesync udp dport 123 accept" in rules
    assert "udp sport 68 udp dport 67 accept" in rules
    assert "udp sport 546 udp dport 547 accept" in rules
    assert "nd-neighbor-solicit" in rules
    assert rules.index("tcp dport 8890 meta skuid root accept") < loopback
    assert rules.index("tcp dport 8890 meta skuid _apt accept") < loopback
    assert rules.index("tcp dport 8890 reject") < loopback
    assert rules.index("tcp dport 8891 meta skuid != policy-gateway reject") < loopback
    assert "meta skuid _apt tcp dport { 80, 443 } accept" not in rules
    assert "meta skuid root tcp dport { 80, 443 } accept" not in rules
    assert "meta skuid policy-gateway tcp dport 443 accept" not in rules
    mcp = render_nft({"STACKJACK_MCP_HOST": "mcp.example"})
    assert "meta skuid policy-gateway tcp dport 443 accept" not in mcp
    siem = render_nft({"SIEM_HOST": "siem.example", "SIEM_PORT": "6514"})
    assert "meta skuid root tcp dport 6514 accept" in siem
    for user in ("egress-proxy", "openwebui", "litellm", "systemd-resolve", "systemd-timesync", "policy-gateway", "_apt"):
        subprocess.run(
            ["sudo", "useradd", "--system", "--shell", "/usr/sbin/nologin", user],
            check=False,
            capture_output=True,
            text=True,
        )
    checked = subprocess.run(
        ["sudo", "nft", "-c", "-f", "-"],
        input=rules,
        text=True,
        capture_output=True,
        check=False,
    )
    assert checked.returncode == 0, checked.stderr
    raw = load_destinations(ROOT / "deploy" / "egress-destinations.yaml")
    assert host_allowed("login.microsoftonline.com", raw, {}) is True
    assert host_allowed("api.anthropic.com", raw, {}) is False
    assert host_allowed("api.anthropic.com", raw, {"ANTHROPIC_BAA_ENABLED": "true"}) is True
    assert host_allowed("example.com", raw, {}) is False


def test_retention_secure_delete_vacuum_and_luks(tmp_path):
    """N-5: integer retention, secure_delete, VACUUM, and the LUKS apply assert."""
    import sqlite3
    from datetime import datetime, timezone

    from stack.retention import CHAT_TEXT_TABLES, purge

    source = (ROOT / "stack" / "retention.py").read_text(encoding="utf-8")
    assert "PRAGMA secure_delete" in source
    assert "VACUUM" in source
    assert "typeof({column}) = 'integer'" in source
    install = (ROOT / "deploy" / "install.sh").read_text(encoding="utf-8")
    assert "check_luks.py" in install
    assert "--target /var/lib/local-ai-stack" in install
    proc = subprocess.run(
        ["python3", str(ROOT / "scripts" / "check_luks.py"), "--self-check"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    db = tmp_path / "webui.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE chat (id TEXT, chat TEXT, updated_at INTEGER)")
    conn.execute("CREATE TABLE chat_message (id TEXT, content TEXT, updated_at INTEGER)")
    conn.execute("CREATE TABLE file (id TEXT, data TEXT, created_at INTEGER)")
    conn.execute("CREATE TABLE feedback (id TEXT, data TEXT, updated_at INTEGER)")
    conn.execute("CREATE TABLE shared_chat (id TEXT, chat TEXT, updated_at INTEGER)")
    conn.execute("CREATE TABLE memory (id TEXT, content TEXT, updated_at INTEGER)")
    conn.execute("CREATE TABLE message (id TEXT, content TEXT, updated_at INTEGER)")
    conn.execute("CREATE TABLE note (id TEXT, data TEXT, updated_at INTEGER)")
    old_s = 946684800
    fresh_s = 4102444800
    phi = "MRN-SYN-0001234"
    conn.execute("INSERT INTO chat VALUES ('old', ?, ?)", (phi, old_s))
    conn.execute("INSERT INTO chat VALUES ('new', 'kept', ?)", (fresh_s,))
    conn.execute("INSERT INTO chat_message VALUES ('m', ?, ?)", (phi, old_s))
    conn.execute("INSERT INTO file VALUES ('f', ?, ?)", (phi, old_s))
    conn.execute("INSERT INTO feedback VALUES ('b', ?, ?)", (phi, old_s))
    conn.execute("INSERT INTO shared_chat VALUES ('s', ?, ?)", (phi, old_s))
    conn.execute("INSERT INTO memory VALUES ('mem', ?, ?)", (phi, old_s))
    conn.execute("INSERT INTO message VALUES ('msg', ?, ?)", (phi, old_s * 1_000_000_000))
    conn.execute("INSERT INTO note VALUES ('n', ?, ?)", (phi, old_s * 1_000_000_000))
    conn.commit()
    conn.close()
    removed = purge(str(db), 30, now=datetime(2026, 10, 16, tzinfo=timezone.utc))
    for name, _column, _unit in CHAT_TEXT_TABLES:
        assert removed[name] >= 1
    assert phi.encode() not in db.read_bytes()


def test_gateway_strips_forwarded_name_and_email(monkeypatch):
    from http.server import ThreadingHTTPServer

    from stack.pipeline import ChatResult
    from stack.server import Handler, strip_forwarded_identity
    from stack.upstream import LiteLLMUpstream

    seen: dict[str, dict[str, str]] = {}

    def fake_handle_chat(**kwargs):
        seen["headers"] = kwargs["headers"]
        seen["user_id"] = kwargs["user_id"]
        seen["user_email"] = kwargs["user_email"]
        return ChatResult(200, {"ok": True})

    monkeypatch.setattr("stack.server.handle_chat", fake_handle_chat)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.gateway_client_key = "gateway-test-key"
    server.deps = (None, None, None, None)
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
        conn.putheader("X-OpenWebUI-User-Name", "Testy McFakerson")
        conn.putheader("X-OpenWebUI-User-Email", "testy@example.invalid")
        conn.putheader("X-Entra-App-Roles", "phi")
        conn.endheaders()
        conn.send(body)
        response = conn.getresponse()
        assert response.status == 200
        response.read()
    finally:
        server.shutdown()
        server.server_close()
    names = {key.lower() for key in seen["headers"]}
    assert "x-openwebui-user-name" not in names
    assert "x-openwebui-user-email" not in names
    assert "x-openwebui-user-id" in names
    assert "x-entra-app-roles" in names
    assert seen["user_id"] == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    assert seen["user_email"] == "testy@example.invalid"
    stripped = strip_forwarded_identity(
        {"X-OpenWebUI-User-Name": "Testy McFakerson", "X-OpenWebUI-User-Id": "id"}
    )
    assert "X-OpenWebUI-User-Name" not in stripped

    from http.server import BaseHTTPRequestHandler

    recorded: dict[str, str] = {}

    class Rec(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            recorded.update({key.lower(): value for key, value in self.headers.items()})
            payload = b'{"id":"x","choices":[]}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, fmt: str, *args) -> None:
            return

    upstream_server = ThreadingHTTPServer(("127.0.0.1", 0), Rec)
    upstream_thread = threading.Thread(target=upstream_server.serve_forever, daemon=True)
    upstream_thread.start()
    uport = upstream_server.server_address[1]
    try:
        upstream = LiteLLMUpstream(f"http://127.0.0.1:{uport}", "virtual-key-fixture")
        upstream.complete(
            {"model": "foundry-gpt", "messages": [{"role": "user", "content": "synthetic"}]},
            team_id="phi",
        )
    finally:
        upstream_server.shutdown()
        upstream_server.server_close()
    assert "x-openwebui-user-name" not in recorded
    assert "x-openwebui-user-email" not in recorded
    assert recorded.get("x-litellm-team-id") == "phi"


def test_proxy_allowlist_is_per_service():
    import socket

    from stack.egress import (
        APT_DESTINATIONS,
        MCP_DESTINATIONS,
        azure_host_ok,
        host_on_named_destination,
        load_destinations,
        proxy_host_allowed,
    )
    from stack.egress_proxy import (
        PROXY_LISTENERS,
        RUNTIME_LISTENERS,
        EgressProxy,
        SniError,
        bind_address,
        client_hello_sni,
        connect_allowed,
        forbidden_ip,
    )

    raw = load_destinations(ROOT / "deploy" / "egress-destinations.yaml")
    env = {
        "ANTHROPIC_BAA_ENABLED": "true",
        "AZURE_API_HOST": "cap-eastus2.openai.azure.com",
        "INSTALL_EGRESS": "1",
        "STACKJACK_MCP_HOST": "mcp.example",
    }
    assert connect_allowed("login.microsoftonline.com", 443, raw, env, "openwebui")
    assert not connect_allowed("api.anthropic.com", 443, raw, env, "openwebui")
    assert not connect_allowed("cap-eastus2.openai.azure.com", 443, raw, env, "openwebui")
    assert connect_allowed("api.anthropic.com", 443, raw, env, "litellm")
    assert connect_allowed("cap-eastus2.openai.azure.com", 443, raw, env, "litellm")
    assert not connect_allowed("login.microsoftonline.com", 443, raw, env, "litellm")
    assert not connect_allowed("api.anthropic.com", 80, raw, env, "litellm")
    for blocked in ("pypi.org", "dl.cloudsmith.io", "pkg.cloudflare.com", "archive.ubuntu.com"):
        assert not proxy_host_allowed(blocked, "litellm", raw, env)
        assert not proxy_host_allowed(blocked, "openwebui", raw, env)
        assert not proxy_host_allowed(blocked, "presidio-analyzer", raw, env)
    assert not proxy_host_allowed("mcp.example", "policy-gateway", raw, {"STACKJACK_MCP_HOST": "mcp.example"})
    assert "presidio-analyzer" not in {user for user, _port in RUNTIME_LISTENERS}
    assert azure_host_ok("cap-eastus2.openai.azure.com")
    assert not azure_host_ok("not-a-region.openai.azure.com")
    assert not azure_host_ok("a.b.openai.azure.com")
    assert not azure_host_ok("foo..eastus2.openai.azure.com")
    assert not azure_host_ok("lab-westeurope.openai.azure.com")
    assert host_on_named_destination("archive.ubuntu.com", 80, raw, env, APT_DESTINATIONS)
    assert host_on_named_destination("dl.cloudsmith.io", 443, raw, env, APT_DESTINATIONS)
    assert not host_on_named_destination("dl.cloudsmith.io", 80, raw, env, APT_DESTINATIONS)
    assert not host_on_named_destination("pkg.cloudflare.com", 443, raw, env, APT_DESTINATIONS)
    assert host_on_named_destination("pypi.org", 443, raw, {"INSTALL_EGRESS": "1"}, APT_DESTINATIONS)
    assert not host_on_named_destination("pypi.org", 443, raw, {}, APT_DESTINATIONS)
    assert host_on_named_destination("mcp.example", 443, raw, env, MCP_DESTINATIONS)
    assert not host_on_named_destination("archive.ubuntu.com", 443, raw, env, MCP_DESTINATIONS)
    assert "is_global" in (ROOT / "stack" / "egress_proxy.py").read_text(encoding="utf-8")
    assert forbidden_ip("127.0.0.1")
    assert forbidden_ip("10.1.2.3")
    assert forbidden_ip("192.168.1.1")
    assert forbidden_ip("100.64.0.1")
    assert forbidden_ip("::ffff:100.64.0.1")
    assert forbidden_ip("169.254.1.1")
    assert forbidden_ip("fd00::1")
    assert forbidden_ip("203.0.113.10")
    assert forbidden_ip("2001:db8::1")
    assert forbidden_ip("224.0.0.1")
    assert not forbidden_ip("8.8.8.8")
    with pytest.raises(SystemExit):
        bind_address("0.0.0.0")
    with pytest.raises(SystemExit):
        bind_address("::")
    assert bind_address("127.0.0.1") == "127.0.0.1"
    dialed: list[tuple[str, int]] = []
    forwarded: list[bytes] = []
    upstream_http: list[bytes] = []

    def connect(host: str, port: int):
        dialed.append((host, port))
        left, right = socket.socketpair()
        if port == 80:
            def reply() -> None:
                data = b""
                while b"\r\n\r\n" not in data and len(data) < 8192:
                    chunk = right.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                upstream_http.append(data)
                right.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                right.close()

            threading.Thread(target=reply, daemon=True).start()
            return left

        def grab() -> None:
            try:
                forwarded.append(right.recv(8192))
            except OSError:
                forwarded.append(b"")
            right.close()

        threading.Thread(target=grab, daemon=True).start()
        return left

    def resolve(host: str) -> list[str]:
        if host == "api.anthropic.com":
            return ["10.1.2.3", "192.168.0.5", "100.64.0.8", "fd00::2"]
        return ["8.8.8.8", "127.0.0.1"]

    proxy = EgressProxy(raw, env, connect=connect, resolve=resolve)
    assert all(sock.getsockname()[0] == "127.0.0.1" for _user, sock in proxy.sockets)
    thread = threading.Thread(target=proxy.serve_forever, daemon=True)
    thread.start()

    def request(user: str, payload: bytes) -> bytes:
        sock = socket.create_connection(("127.0.0.1", proxy.port_for(user)), timeout=2)
        sock.settimeout(2)
        sock.sendall(payload)
        data = b""
        while b"\r\n" not in data:
            chunk = sock.recv(256)
            if not chunk:
                break
            data += chunk
        sock.close()
        return data

    try:
        entra = request("openwebui", b"CONNECT login.microsoftonline.com:443 HTTP/1.1\r\nHost: login.microsoftonline.com:443\r\n\r\n")
        assert entra.startswith(b"HTTP/1.1 200")
        denied = request("openwebui", b"CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n\r\n")
        assert denied.startswith(b"HTTP/1.1 403")
        azure_denied = request(
            "openwebui",
            b"CONNECT cap-eastus2.openai.azure.com:443 HTTP/1.1\r\nHost: cap-eastus2.openai.azure.com:443\r\n\r\n",
        )
        assert azure_denied.startswith(b"HTTP/1.1 403")
        private = request("litellm", b"CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n\r\n")
        assert private.startswith(b"HTTP/1.1 403")
        azure = request(
            "litellm",
            b"CONNECT cap-eastus2.openai.azure.com:443 HTTP/1.1\r\nHost: cap-eastus2.openai.azure.com:443\r\n\r\n",
        )
        assert azure.startswith(b"HTTP/1.1 200")
        wrong_port = request("litellm", b"CONNECT cap-eastus2.openai.azure.com:80 HTTP/1.1\r\nHost: cap-eastus2.openai.azure.com:80\r\n\r\n")
        assert wrong_port.startswith(b"HTTP/1.1 403")
        get = request("litellm", b"GET http://cap-eastus2.openai.azure.com/ HTTP/1.1\r\nHost: cap-eastus2.openai.azure.com\r\n\r\n")
        assert get.startswith(b"HTTP/1.1 405")
        apt = request("apt", b"CONNECT archive.ubuntu.com:443 HTTP/1.1\r\nHost: archive.ubuntu.com:443\r\n\r\n")
        assert apt.startswith(b"HTTP/1.1 200")
        apt_host = request("apt", b"CONNECT archive.ubuntu.com:443 HTTP/1.1\r\nHost: evil.example:443\r\n\r\n")
        assert apt_host.startswith(b"HTTP/1.1 403")
        cloud = request("apt", b"CONNECT pkg.cloudflare.com:443 HTTP/1.1\r\nHost: pkg.cloudflare.com:443\r\n\r\n")
        assert cloud.startswith(b"HTTP/1.1 403")
        http_ok = request(
            "apt",
            b"GET http://archive.ubuntu.com/ubuntu/ HTTP/1.1\r\nHost: archive.ubuntu.com\r\nConnection: keep-alive\r\n\r\n",
        )
        assert http_ok.startswith(b"HTTP/1.1 200")
        http_bad = request(
            "apt",
            b"GET http://archive.ubuntu.com/ubuntu/ HTTP/1.1\r\nHost: evil.example\r\n\r\n",
        )
        assert http_bad.startswith(b"HTTP/1.1 403")
        duplicate_host = request(
            "apt",
            b"GET http://archive.ubuntu.com/ubuntu/ HTTP/1.1\r\nHost: archive.ubuntu.com\r\nHost: archive.ubuntu.com\r\n\r\n",
        )
        assert duplicate_host.startswith(b"HTTP/1.1 400")
        duplicate_te = request(
            "apt",
            b"GET http://archive.ubuntu.com/ubuntu/ HTTP/1.1\r\nHost: archive.ubuntu.com\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n\r\n",
        )
        assert duplicate_te.startswith(b"HTTP/1.1 400")
        mcp = request("policy-gateway", b"CONNECT mcp.example:443 HTTP/1.1\r\nHost: mcp.example:443\r\n\r\n")
        assert mcp.startswith(b"HTTP/1.1 200")
        mcp_bad = request(
            "policy-gateway",
            b"CONNECT archive.ubuntu.com:443 HTTP/1.1\r\nHost: archive.ubuntu.com:443\r\n\r\n",
        )
        assert mcp_bad.startswith(b"HTTP/1.1 403")
        hello = _client_hello("login.microsoftonline.com")
        assert client_hello_sni(hello) == "login.microsoftonline.com"
        with pytest.raises(SniError) as missing:
            client_hello_sni(_client_hello(None))
        assert missing.value.reason == "missing"
        with pytest.raises(SniError) as ech:
            client_hello_sni(_client_hello("login.microsoftonline.com", ech=True))
        assert ech.value.reason == "ech"
        sock = socket.create_connection(("127.0.0.1", proxy.port_for("openwebui")), timeout=2)
        sock.settimeout(2)
        sock.sendall(b"CONNECT login.microsoftonline.com:443 HTTP/1.1\r\nHost: login.microsoftonline.com:443\r\n\r\n")
        established = b""
        while b"\r\n\r\n" not in established:
            established += sock.recv(256)
        assert established.startswith(b"HTTP/1.1 200")
        dials_before = len(dialed)
        sock.sendall(hello)
        deadline = time.time() + 2
        while len(forwarded) < 1 and time.time() < deadline:
            time.sleep(0.01)
        sock.close()
        assert forwarded == [hello]
        assert len(dialed) == dials_before + 1
        mismatch = socket.create_connection(("127.0.0.1", proxy.port_for("apt")), timeout=2)
        mismatch.settimeout(2)
        mismatch.sendall(b"CONNECT archive.ubuntu.com:443 HTTP/1.1\r\nHost: archive.ubuntu.com:443\r\n\r\n")
        opened = b""
        while b"\r\n\r\n" not in opened:
            opened += mismatch.recv(256)
        assert opened.startswith(b"HTTP/1.1 200")
        dials_before = len(dialed)
        mismatch.sendall(_client_hello("evil.example"))
        assert mismatch.recv(16) == b""
        mismatch.close()
        assert len(dialed) == dials_before
    finally:
        proxy.close()
    assert upstream_http and b"\r\nConnection: close\r\n" in upstream_http[0]
    assert b"keep-alive" not in upstream_http[0].lower()
    assert ("8.8.8.8", 443) in dialed
    assert ("8.8.8.8", 80) in dialed
    assert ("10.1.2.3", 443) not in dialed
    assert ("127.0.0.1", 443) not in dialed
    litellm = (ROOT / "deploy" / "systemd" / "litellm.service").read_text(encoding="utf-8")
    webui = (ROOT / "deploy" / "systemd" / "open-webui.service").read_text(encoding="utf-8")
    analyzer = (ROOT / "deploy" / "systemd" / "presidio-analyzer.service").read_text(encoding="utf-8")
    assert "HTTPS_PROXY=http://127.0.0.1:8889" in litellm
    assert "HTTPS_PROXY=http://127.0.0.1:8888" in webui
    assert "HTTPS_PROXY=" not in analyzer
    gateway = (ROOT / "deploy" / "systemd" / "policy-gateway.service").read_text(encoding="utf-8")
    assert "HTTPS_PROXY=http://127.0.0.1:8891" in gateway
    assert "NO_PROXY=127.0.0.1,127.0.0.2,localhost" in gateway
    assert {user for user, _port in PROXY_LISTENERS} >= {"openwebui", "litellm", "apt", "policy-gateway"}
    install = (ROOT / "deploy" / "install.sh").read_text(encoding="utf-8")
    assert install.index("99local-ai-proxy") < install.index("\napt-get update")
    assert install.rindex("systemctl restart egress-proxy.service") < install.rindex("99local-ai-proxy")
    assert "NTP=ntp.ubuntu.com" in (ROOT / "deploy" / "systemd" / "timesyncd.conf.d" / "local-ai.conf").read_text(encoding="utf-8")
    assert "0.pool.ntp.org" not in (ROOT / "deploy" / "egress-destinations.yaml").read_text(encoding="utf-8")
    assert "time.cloudflare.com" not in (ROOT / "deploy" / "egress-destinations.yaml").read_text(encoding="utf-8")
    nft_unit = (ROOT / "deploy" / "systemd" / "local-ai-egress-nft.service").read_text(encoding="utf-8")
    assert "Before=network-pre.target" in nft_unit
    assert "Wants=network-pre.target" in nft_unit
    assert "WantedBy=sysinit.target" in nft_unit
    assert "WantedBy=multi-user.target" in nft_unit
    assert "network-pre.target.wants/local-ai-egress-nft.service" in install
    assert "--nft-only" in (ROOT / "deploy" / "egress-refresh.sh").read_text(encoding="utf-8")


def test_sni_refusals_deadline_cap_and_port80():
    import socket

    from stack.egress import load_destinations
    from stack.egress_proxy import (
        CONNECTION_CAP,
        HANDSHAKE_DEADLINE,
        EgressProxy,
        SniError,
        _read_tls_record,
        client_hello_sni,
        require_client_hello,
    )

    assert HANDSHAKE_DEADLINE == 10
    assert CONNECTION_CAP == 64
    design = (ROOT / "docs" / "egress-proxy.md").read_text(encoding="utf-8")
    assert "duplicate SNI extension" in design
    assert "10 seconds" in design
    assert "64" in design
    assert "Any Transfer-Encoding" in design
    assert "duplicate Content-Length" in design
    assert "obs-fold" in design
    with pytest.raises(SniError) as mismatch:
        require_client_hello(_client_hello("evil.example"), "archive.ubuntu.com")
    assert mismatch.value.reason == "mismatch"
    assert require_client_hello(_client_hello("Archive.Ubuntu.com."), "archive.ubuntu.com") == "archive.ubuntu.com"
    with pytest.raises(SniError) as multi:
        client_hello_sni(_client_hello("archive.ubuntu.com", extra_names=("evil.example",)))
    assert multi.value.reason == "malformed"
    with pytest.raises(SniError) as duplicate:
        client_hello_sni(_client_hello("archive.ubuntu.com", duplicate=True))
    assert duplicate.value.reason == "duplicate"
    with pytest.raises(SniError) as nontls:
        client_hello_sni(b"\x17\x03\x03\x00\x01\xff")
    assert nontls.value.reason == "malformed"
    oversize = b"\x16\x03\x01" + (16385).to_bytes(2, "big") + (b"\x00" * 16385)
    with pytest.raises(SniError) as huge:
        client_hello_sni(oversize)
    assert huge.value.reason == "malformed"

    left, right = socket.socketpair()
    right.sendall(b"\x16\x03\x01\x00\x20")
    right.close()
    with pytest.raises(SniError) as truncated:
        _read_tls_record(left, time.monotonic() + 1)
    assert truncated.value.reason == "missing"
    left.close()

    left, right = socket.socketpair()
    right.sendall(b"\x16\x03\x01" + (16385).to_bytes(2, "big"))
    right.close()
    with pytest.raises(SniError) as declared:
        _read_tls_record(left, time.monotonic() + 1)
    assert declared.value.reason == "malformed"
    left.close()

    left, right = socket.socketpair()
    right.sendall(b"\x17\x03\x03\x00\x01\xff")
    with pytest.raises(SniError) as application_data:
        _read_tls_record(left, time.monotonic() + 1)
    assert application_data.value.reason == "malformed"
    left.close()
    right.close()

    raw = load_destinations(ROOT / "deploy" / "egress-destinations.yaml")
    env = {"INSTALL_EGRESS": "1"}
    dialed: list[tuple[str, int]] = []

    def connect(host: str, port: int):
        dialed.append((host, port))
        one, two = socket.socketpair()
        if port == 80:
            def reply() -> None:
                try:
                    two.recv(8192)
                    two.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                except OSError:
                    pass
                two.close()

            threading.Thread(target=reply, daemon=True).start()
            return one
        two.close()
        return one

    def resolve(_host: str) -> list[str]:
        return ["8.8.8.8"]

    proxy = EgressProxy(
        raw,
        env,
        listeners=(("openwebui", 0), ("apt", 0)),
        connect=connect,
        resolve=resolve,
        handshake_deadline=2,
    )
    threading.Thread(target=proxy.serve_forever, daemon=True).start()

    def opened(user: str, host: str) -> socket.socket:
        sock = socket.create_connection(("127.0.0.1", proxy.port_for(user)), timeout=2)
        sock.settimeout(2)
        sock.sendall(f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n".encode())
        data = b""
        while b"\r\n\r\n" not in data:
            data += sock.recv(256)
        assert data.startswith(b"HTTP/1.1 200")
        return sock

    def refused(user: str, host: str, payload: bytes, *, shutdown: bool = False, timeout: float = 2) -> None:
        before = len(dialed)
        sock = opened(user, host)
        sock.settimeout(timeout)
        sock.sendall(payload)
        if shutdown:
            sock.shutdown(socket.SHUT_WR)
        try:
            assert sock.recv(16) == b""
        except ConnectionResetError:
            pass
        sock.close()
        assert len(dialed) == before

    def http(payload: bytes) -> bytes:
        sock = socket.create_connection(("127.0.0.1", proxy.port_for("apt")), timeout=2)
        sock.settimeout(2)
        sock.sendall(payload)
        data = b""
        while b"\r\n" not in data:
            chunk = sock.recv(256)
            if not chunk:
                break
            data += chunk
        sock.close()
        return data

    try:
        refused("openwebui", "login.microsoftonline.com", _client_hello("evil.example"))
        refused(
            "openwebui",
            "login.microsoftonline.com",
            _client_hello("login.microsoftonline.com", extra_names=("evil.example",)),
        )
        refused("openwebui", "login.microsoftonline.com", _client_hello("login.microsoftonline.com", duplicate=True))
        refused("openwebui", "login.microsoftonline.com", b"\x16\x03\x01\x00\x20", shutdown=True)
        refused("openwebui", "login.microsoftonline.com", b"\x16\x03\x01" + (16385).to_bytes(2, "big"), timeout=0.3)
        refused("openwebui", "login.microsoftonline.com", b"\x17\x03\x03\x00\x01\xff")
        assert http(
            b"GET http://archive.ubuntu.com/ubuntu/ HTTP/1.1\r\nHost: archive.ubuntu.com\r\nTransfer-Encoding: chunked\r\n\r\n"
        ).startswith(b"HTTP/1.1 400")
        assert http(
            b"GET http://archive.ubuntu.com/ubuntu/ HTTP/1.1\r\nHost: archive.ubuntu.com\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n"
        ).startswith(b"HTTP/1.1 400")
        assert http(
            b"GET http://archive.ubuntu.com/ubuntu/ HTTP/1.1\r\n Host: archive.ubuntu.com\r\n\r\n"
        ).startswith(b"HTTP/1.1 400")
        assert http(
            b"GET http://archive.ubuntu.com/ubuntu/ HTTP/1.1\r\nHost: archive.ubuntu.com\r\nContent-Length: 0\r\n\r\n"
        ).startswith(b"HTTP/1.1 200")
    finally:
        proxy.close()

    quiet = EgressProxy(
        raw,
        env,
        listeners=(("openwebui", 0),),
        connect=connect,
        resolve=resolve,
        handshake_deadline=0.05,
    )
    threading.Thread(target=quiet.serve_forever, daemon=True).start()
    try:
        stalled = socket.create_connection(("127.0.0.1", quiet.port_for("openwebui")), timeout=2)
        stalled.settimeout(1)
        assert stalled.recv(64).startswith(b"HTTP/1.1 408")
        stalled.close()
        before = len(dialed)
        tunnel = socket.create_connection(("127.0.0.1", quiet.port_for("openwebui")), timeout=2)
        tunnel.settimeout(1)
        tunnel.sendall(b"CONNECT login.microsoftonline.com:443 HTTP/1.1\r\nHost: login.microsoftonline.com:443\r\n\r\n")
        established = b""
        while b"\r\n\r\n" not in established:
            established += tunnel.recv(256)
        assert established.startswith(b"HTTP/1.1 200")
        assert tunnel.recv(16) == b""
        tunnel.close()
        assert len(dialed) == before
    finally:
        quiet.close()

    gate = threading.Event()
    started = threading.Event()

    def blocking_connect(host: str, port: int):
        dialed.append((host, port))
        started.set()
        assert gate.wait(timeout=3)
        one, two = socket.socketpair()
        two.close()
        return one

    capped = EgressProxy(
        raw,
        env,
        listeners=(("openwebui", 0),),
        connect=blocking_connect,
        resolve=resolve,
        connection_cap=1,
        handshake_deadline=5,
    )
    threading.Thread(target=capped.serve_forever, daemon=True).start()
    try:
        first = socket.create_connection(("127.0.0.1", capped.port_for("openwebui")), timeout=2)
        first.settimeout(2)
        first.sendall(b"CONNECT login.microsoftonline.com:443 HTTP/1.1\r\nHost: login.microsoftonline.com:443\r\n\r\n")
        established = b""
        while b"\r\n\r\n" not in established:
            established += first.recv(256)
        assert established.startswith(b"HTTP/1.1 200")
        first.sendall(_client_hello("login.microsoftonline.com"))
        assert started.wait(timeout=2)
        second = socket.create_connection(("127.0.0.1", capped.port_for("openwebui")), timeout=2)
        second.settimeout(1)
        try:
            closed = second.recv(32)
        except ConnectionResetError:
            closed = b""
        assert closed == b""
        second.close()
        gate.set()
        first.close()
    finally:
        gate.set()
        capped.close()


def test_open_webui_refuses_zero_client_id():
    env = os.environ.copy()
    env["MICROSOFT_CLIENT_ID"] = "00000000-0000-0000-0000-000000000000"
    proc = subprocess.run(
        ["bash", str(ROOT / "deploy" / "open-webui-run.sh")],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 1
    assert "refusing zero-GUID MICROSOFT_CLIENT_ID" in proc.stderr
    assert "refusing zero-GUID MICROSOFT_CLIENT_ID" in (ROOT / "deploy" / "install.sh").read_text(encoding="utf-8")


def test_least_privilege_is_not_claimed_tested_here():
    """PR #3's test_best_practices.py is not in this tree. Do not mark those practices tested."""
    path = ROOT / "tests" / "test_best_practices.py"
    if not path.exists():
        return
    text = path.read_text(encoding="utf-8")
    for practice in ("ms.azure-mcp-least-privilege", "payload.least-privilege"):
        assert practice not in text or "tested" not in text.split(practice, 1)[1][:80]
