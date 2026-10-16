"""Acceptance tests 1–11. Synthetic fixtures only."""

from __future__ import annotations

import base64
import json
import stat
from dataclasses import replace
from pathlib import Path

import pytest
import yaml

from stack.audit import AuditLog
from stack.egress import host_allowed, load_destinations
from stack.errors import PolicyError
from stack.masking import load_recognizers, mask_text, presidio_ad_hoc, residual_entities
from stack.phi_scan import contains_raw_phi
from stack.pipeline import McpUpstream, Upstream, handle_chat, handle_mcp, record_config_change
from stack.policy import FoundryRuntime, load_policy
from stack.presidio_client import PresidioClient
from stack.retention import purge
from tests.support.fake_presidio import FakePresidio

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = json.loads((ROOT / "tests" / "fixtures" / "synthetic.json").read_text(encoding="utf-8"))
HEADER = "SYNTHETIC — FAKE DATA — NOT REAL PERSONS"
USER = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
RAW_PROMPT = FIXTURES["prompt"]
RAW_RESPONSE = "The fictional patient Testy McFakerson has MRN MRN-SYN-0001234 and SSN 000-00-0000."


@pytest.fixture(scope="module")
def recognizers():
    return load_recognizers(ROOT / "presidio" / "recognizers")


@pytest.fixture(scope="module")
def policy():
    return load_policy(ROOT / "litellm" / "policy.yaml")


@pytest.fixture
def presidio_services(recognizers, policy):
    analyzer = FakePresidio(recognizers, policy.mask_score_threshold)
    anonymizer = FakePresidio(recognizers, policy.mask_score_threshold)
    client = PresidioClient(
        analyzer.url,
        anonymizer.url,
        timeout=0.3,
        recognizers=recognizers,
        threshold=policy.mask_score_threshold,
    )
    yield client, analyzer, anonymizer
    analyzer.stop()
    anonymizer.stop()


@pytest.fixture
def audit(tmp_path, recognizers, policy):
    return AuditLog(tmp_path / "audit.db", recognizers, policy.mask_score_threshold)


def _foundry() -> FoundryRuntime:
    return FoundryRuntime(
        deployment="dep-placeholder",
        model_family="gpt-4.1",
        region="eastus2",
        api_base="https://cap-eastus2.openai.azure.com/",
    )


def _policy_for(policy, backend: str):
    if backend == "anthropic":
        return replace(policy, anthropic_baa_enabled=True)
    if backend == "azure":
        return policy
    if backend == "azure_ai":
        return replace(policy, foundry=replace(policy.foundry, azure_ai_enabled=True))
    raise AssertionError(backend)


def _model(backend: str) -> str:
    if backend == "anthropic":
        return "anthropic/claude-sonnet-4-5"
    if backend == "azure":
        return "azure/dep-placeholder"
    return "azure_ai/marketplace-fixture"


def _chat(backend, policy, presidio, audit, **overrides):
    upstream = Upstream()
    body = {
        "model": _model(backend),
        "messages": [{"role": "user", "content": RAW_PROMPT}],
        "max_tokens": 32,
    }
    body.update(overrides.pop("body", {}))
    headers = {"X-Entra-App-Roles": "phi"}
    headers.update(overrides.pop("headers", {}))
    try:
        result = handle_chat(
            path=overrides.pop("path", "/v1/chat/completions"),
            headers=headers,
            body=body,
            user_id=overrides.pop("user_id", USER),
            policy=_policy_for(policy, backend),
            foundry=_foundry(),
            presidio=presidio,
            upstream=upstream,
            audit=audit,
            mock_response=overrides.pop("mock_response", None),
        )
    except PolicyError as exc:
        return exc, upstream
    return result, upstream


@pytest.mark.parametrize("backend", ["anthropic", "azure", "azure_ai"])
def test_01_pre_call_redaction(backend, policy, presidio_services, audit, recognizers):
    client, _, _ = presidio_services
    result, upstream = _chat(backend, policy, client, audit)
    assert getattr(result, "status", None) == 200
    assert len(upstream.calls) == 1
    sent = upstream.calls[0]["messages"][0]["content"]
    assert not residual_entities(sent, recognizers, policy.mask_score_threshold)
    assert "<MRN>" in sent
    assert "<PERSON>" in sent
    assert "MRN-SYN-0001234" not in sent
    assert "Testy McFakerson" not in sent


@pytest.mark.parametrize("backend", ["anthropic", "azure", "azure_ai"])
def test_02_post_call_redaction(backend, policy, presidio_services, audit, recognizers):
    client, _, _ = presidio_services
    result, upstream = _chat(backend, policy, client, audit, mock_response=RAW_RESPONSE)
    assert result.status == 200
    content = result.body["choices"][0]["message"]["content"]
    assert "Testy McFakerson" not in content
    assert "MRN-SYN-0001234" not in content
    assert "<PERSON>" in content and "<MRN>" in content
    assert not residual_entities(content, recognizers, policy.mask_score_threshold)


def test_03_recognizers_and_recall(policy, recognizers):
    hits: dict[str, list[bool]] = {}
    for row in FIXTURES["canonical"]:
        masked, _entities = mask_text(row["text"], recognizers, policy.mask_score_threshold)
        detected = f"<{row['entity']}>" in masked and row["text"] != masked
        hits.setdefault(row["entity"], []).append(detected)
        assert not residual_entities(masked, recognizers, policy.mask_score_threshold)
    for entity, floor in policy.recall_floors.items():
        values = hits[entity]
        recall = sum(values) / len(values)
        assert recall >= floor, entity
    for text in FIXTURES["negative"]:
        masked, entities = mask_text(text, recognizers, policy.mask_score_threshold)
        assert masked == text, text
        assert entities == []


def test_03_adversarial_regression(policy, recognizers):
    for row in FIXTURES["adversarial"]:
        if row.get("encoding") == "base64":
            text = base64.b64encode(row["plain"].encode()).decode()
        else:
            text = row["text"]
        masked, _entities = mask_text(text, recognizers, policy.mask_score_threshold)
        assert f"<{row['entity']}>" in masked or "<OBFUSCATED_PHI>" in masked
        assert not residual_entities(masked, recognizers, policy.mask_score_threshold)


@pytest.mark.parametrize("backend", ["anthropic", "azure", "azure_ai"])
@pytest.mark.parametrize(
    "failure",
    ["analyzer_down", "anonymizer_down", "timeout", "http_500", "bad_json", "object_json"],
)
def test_04_fail_closed(backend, failure, policy, presidio_services, audit):
    client, analyzer, anonymizer = presidio_services
    if failure == "analyzer_down":
        client.analyzer_url = "http://127.0.0.1:9"
    elif failure == "anonymizer_down":
        client.anonymizer_url = "http://127.0.0.1:9"
    elif failure == "timeout":
        analyzer.set_mode("timeout")
    else:
        analyzer.set_mode(failure)
    result, upstream = _chat(backend, policy, client, audit)
    assert isinstance(result, PolicyError)
    assert result.status == 503
    assert RAW_PROMPT not in result.message
    assert "MRN-SYN" not in result.message
    assert upstream.calls == []


@pytest.mark.parametrize("backend", ["anthropic", "azure", "azure_ai"])
def test_04_streaming_rejected(backend, policy, presidio_services, audit):
    client, _, _ = presidio_services
    result, upstream = _chat(backend, policy, client, audit, body={"stream": True})
    assert isinstance(result, PolicyError)
    assert result.code == "streaming_disabled"
    assert upstream.calls == []


@pytest.mark.parametrize(
    "path",
    ["/v1/completions", "/v1/embeddings", "/v1/responses", "/v1/messages", "/v1/files", "/v1/batches", "/anthropic/v1/messages"],
)
def test_04_untested_routes_rejected(path, policy, presidio_services, audit):
    client, _, _ = presidio_services
    result, upstream = _chat("anthropic", policy, client, audit, path=path)
    assert isinstance(result, PolicyError)
    assert result.code == "route_disabled"
    assert upstream.calls == []


def test_05_pre_mcp_call(policy, presidio_services, audit, recognizers):
    client, _, _ = presidio_services
    allowed = replace(
        policy,
        mcp_allowed_upstreams=(
            {"server": "stackjack-readonly", "kind": "stackjack", "tool": "list_tickets"},
        ),
    )
    upstream = McpUpstream()
    result = handle_mcp(
        server="stackjack-readonly",
        tool="list_tickets",
        arguments={"query": "MRN-SYN-0001234 for Testy McFakerson", "_mock_result": RAW_RESPONSE},
        user_id=USER,
        policy=allowed,
        presidio=client,
        upstream=upstream,
        audit=audit,
    )
    assert len(upstream.calls) == 1
    sent = json.dumps(upstream.calls[0]["arguments"])
    assert "MRN-SYN-0001234" not in sent
    assert "<MRN>" in sent
    rendered = json.dumps(result)
    assert "Testy McFakerson" not in rendered
    assert not residual_entities(rendered, recognizers, policy.mask_score_threshold)
    blocked = McpUpstream()
    with pytest.raises(PolicyError) as exc:
        handle_mcp(
            server="anywhere",
            tool="export_all",
            arguments={"query": "hello"},
            user_id=USER,
            policy=policy,
            presidio=client,
            upstream=blocked,
            audit=audit,
        )
    assert exc.value.code == "mcp_not_allowlisted"
    assert blocked.calls == []


def test_06_audit_has_user_and_no_raw_phi(policy, presidio_services, audit, recognizers):
    client, _, _ = presidio_services
    result, _upstream = _chat("azure", policy, client, audit, mock_response=RAW_RESPONSE)
    assert result.status == 200
    rows = audit.rows()
    assert rows
    blob = json.dumps(rows)
    assert USER in blob
    assert not contains_raw_phi(blob, recognizers, policy.mask_score_threshold)
    assert "MRN-SYN-0001234" not in blob
    assert "Testy McFakerson" not in blob
    change = record_config_change(audit, policy, USER, (ROOT / "litellm" / "policy.yaml").read_bytes())
    assert change["event_type"] == "config_change"
    assert change["user_id"] == USER
    assert change["config_hash"]
    webui_env = (ROOT / "deploy" / "env" / "open-webui.env").read_text(encoding="utf-8")
    assert "AUDIT_LOG_LEVEL=METADATA" in webui_env
    assert "GLOBAL_LOG_LEVEL=WARNING" in webui_env
    litellm_unit = (ROOT / "deploy" / "systemd" / "litellm.service").read_text(encoding="utf-8")
    assert "LITELLM_LOG=ERROR" in litellm_unit
    journal = (ROOT / "deploy" / "journald" / "local-ai.conf").read_text(encoding="utf-8")
    assert "SystemMaxFileSize=10M" in journal
    assert "SystemMaxFiles=5" in journal


def test_06_openwebui_db_scan_and_retention(tmp_path, recognizers, policy):
    import sqlite3

    from stack.retention import CHAT_TEXT_TABLES

    db = tmp_path / "webui.db"
    conn = sqlite3.connect(db)
    # Open WebUI stores these as integers: seconds for chat/file, nanoseconds for message/note.
    conn.execute("CREATE TABLE chat (id TEXT, user_id TEXT, title TEXT, chat TEXT, updated_at INTEGER)")
    conn.execute("CREATE TABLE chat_message (id TEXT, content TEXT, updated_at INTEGER)")
    conn.execute("CREATE TABLE file (id TEXT, data TEXT, created_at INTEGER)")
    conn.execute("CREATE TABLE feedback (id TEXT, data TEXT, updated_at INTEGER)")
    conn.execute("CREATE TABLE shared_chat (id TEXT, chat TEXT, updated_at INTEGER)")
    conn.execute("CREATE TABLE memory (id TEXT, content TEXT, updated_at INTEGER)")
    conn.execute("CREATE TABLE message (id TEXT, content TEXT, updated_at INTEGER)")
    conn.execute("CREATE TABLE note (id TEXT, data TEXT, updated_at INTEGER)")
    old_s = 946684800
    fresh_s = 4102444800
    old_ns = old_s * 1_000_000_000
    fresh_ns = fresh_s * 1_000_000_000
    phi = "MRN-SYN-0001234"
    conn.execute("INSERT INTO chat VALUES ('1', ?, 't', ?, ?)", (USER, phi, old_s))
    conn.execute("INSERT INTO chat VALUES ('2', ?, 't', 'no identifier here', ?)", (USER, fresh_s))
    conn.execute("INSERT INTO chat_message VALUES ('m', ?, ?)", (phi, old_s))
    conn.execute("INSERT INTO file VALUES ('f', ?, ?)", (phi, old_s))
    conn.execute("INSERT INTO feedback VALUES ('b', ?, ?)", (phi, old_s))
    conn.execute("INSERT INTO shared_chat VALUES ('s', ?, ?)", (phi, old_s))
    conn.execute("INSERT INTO memory VALUES ('mem', ?, ?)", (phi, old_s))
    conn.execute("INSERT INTO message VALUES ('msg-old', ?, ?)", (phi, old_ns))
    conn.execute("INSERT INTO message VALUES ('msg-new', 'kept', ?)", (fresh_ns,))
    conn.execute("INSERT INTO note VALUES ('n', ?, ?)", (phi, old_ns))
    conn.commit()
    conn.close()
    raw = Path(db).read_bytes()
    assert phi.encode() in raw
    assert contains_raw_phi(raw.decode("utf-8", "ignore"), recognizers, policy.mask_score_threshold)
    moment = __import__("datetime").datetime(2026, 10, 16, tzinfo=__import__("datetime").timezone.utc)
    removed = purge(str(db), policy.chat_retention_days, now=moment)
    for name, _column, _unit in CHAT_TEXT_TABLES:
        assert removed[name] >= 1
    conn = sqlite3.connect(db)
    left = conn.execute("SELECT chat FROM chat").fetchall()
    kept_message = conn.execute("SELECT id FROM message").fetchall()
    conn.close()
    assert left == [("no identifier here",)]
    assert kept_message == [("msg-new",)]
    vacuumed = Path(db).read_bytes()
    assert phi.encode() not in vacuumed


def test_07_and_09_exposure_and_tunnel():
    from scripts.check_tree import check

    assert check() == []
    tunnel = (ROOT / "deploy" / "cloudflared" / "config.yml").read_text(encoding="utf-8")
    assert "http_status:404" in tunnel
    for target in ("open-webui", "litellm", "policy-gateway"):
        assert target not in tunnel
    egress = load_destinations(ROOT / "deploy" / "egress-destinations.yaml")
    assert not host_allowed("api.anthropic.com", egress, {})
    assert host_allowed("api.anthropic.com", egress, {"ANTHROPIC_BAA_ENABLED": "true"})
    assert not host_allowed("api.anthropic.com", egress, {"ANTHROPIC_BAA_ENABLED": "yes"})
    assert not host_allowed("pypi.org", egress, {})
    assert host_allowed("pypi.org", egress, {"INSTALL_EGRESS": "1"})
    assert host_allowed("login.microsoftonline.com", egress, {})
    assert not host_allowed("region1.v2.argotunnel.com", egress, {})
    assert not host_allowed("cloudflare.com", egress, {})
    azure_env = {"AZURE_API_HOST": "cap-eastus2.openai.azure.com"}
    assert host_allowed("cap-eastus2.openai.azure.com", egress, azure_env)
    assert not host_allowed("other.openai.azure.com", egress, azure_env)


def test_08_secrets_are_files_not_env():
    assert not (ROOT / "docker-compose.yml").exists()
    services = yaml.safe_load((ROOT / "deploy" / "services.yaml").read_text(encoding="utf-8"))
    creds = {cred for app in services["apps"] for cred in app["credentials"]}
    assert "litellm_master_key" in creds
    for app in services["apps"]:
        unit = (ROOT / "deploy" / "systemd" / app["unit"]).read_text(encoding="utf-8")
        for cred in app["credentials"]:
            if app["unit"] == "litellm.service" and cred == "anthropic_api_key":
                assert f"LoadCredential={cred}:" not in unit
                dropin = (ROOT / "deploy" / "systemd" / "litellm.service.d" / "10-anthropic.conf").read_text(encoding="utf-8")
                assert f"LoadCredential={cred}:" in dropin
                continue
            assert f"LoadCredential={cred}:" in unit
        assert "sk-" not in unit
    for path in (ROOT / "deploy" / "env").glob("*.env"):
        text = path.read_text(encoding="utf-8")
        assert "sk-" not in text
        assert "example-not-a-secret" not in text
    example = (ROOT / ".env.example").read_text(encoding="utf-8")
    assert "example-not-a-secret" in example
    assert "sk-ant-" not in example
    assert "0600" in (ROOT / "deploy" / "write-secret.sh").read_text(encoding="utf-8")
    cloud = (ROOT / "deploy" / "systemd" / "cloudflared.service").read_text(encoding="utf-8")
    assert "/etc/cloudflared/credentials.json" in cloud


def test_10_and_11_allowlist(policy, presidio_services, audit):
    client, _, _ = presidio_services
    for model in ("gpt-4o", "bedrock/claude", "vertex_ai/claude", "anthropic/claude-unknown"):
        result, upstream = _chat("anthropic", policy, client, audit, body={"model": model})
        assert isinstance(result, PolicyError)
        assert result.code in {"model_not_allowlisted", "anthropic_baa_disabled"}
        assert upstream.calls == []
    result, upstream = _chat(
        "anthropic",
        policy,
        client,
        audit,
        headers={"anthropic-beta": "computer-use-2025-01-24"},
    )
    assert isinstance(result, PolicyError)
    assert result.code == "beta_header_blocked"
    assert upstream.calls == []
    result, upstream = _chat(
        "anthropic",
        policy,
        client,
        audit,
        body={"tools": [{"type": "web_search"}]},
    )
    assert result.code == "tool_blocked"
    assert upstream.calls == []
    upstream = Upstream()
    with pytest.raises(PolicyError) as exc:
        handle_chat(
            path="/v1/chat/completions",
            headers={},
            body={"model": "anthropic/claude-sonnet-4-5", "messages": [{"role": "user", "content": "hello"}]},
            user_id=USER,
            policy=policy,
            foundry=_foundry(),
            presidio=client,
            upstream=upstream,
            audit=audit,
        )
    assert exc.value.code == "anthropic_baa_disabled"
    assert upstream.calls == []
    config = (ROOT / "litellm" / "config.yaml").read_text(encoding="utf-8")
    assert "telemetry: false" in config
    assert "callbacks: []" in config
    assert "success_callback: []" in config
    assert "store_prompts_in_spend_logs: false" in config
    assert "turn_off_message_logging: true" in config
    for banned in ("langfuse", "helicone", "lunary"):
        assert banned not in config.lower()
    assert policy.anthropic_baa_enabled is False
    assert policy.streaming_enabled is False
    assert policy.foundry.azure_ai_enabled is False
    assert policy.foundry.abuse_monitoring_opt_out is False
    assert policy.anthropic_zdr_confirmed_by_cap is False


def test_foundry_region_and_family(policy, presidio_services, audit):
    client, _, _ = presidio_services
    bad_region = FoundryRuntime("dep-placeholder", "gpt-4.1", "westeurope", "https://cap.openai.azure.com/")
    upstream = Upstream()
    with pytest.raises(PolicyError) as exc:
        handle_chat(
            path="/v1/chat/completions",
            headers={},
            body={"model": "azure/dep-placeholder", "messages": [{"role": "user", "content": "hello"}]},
            user_id=USER,
            policy=policy,
            foundry=bad_region,
            presidio=client,
            upstream=upstream,
            audit=audit,
        )
    assert exc.value.code == "region_not_allowed"
    assert upstream.calls == []
    marketplace = Upstream()
    with pytest.raises(PolicyError) as exc:
        handle_chat(
            path="/v1/chat/completions",
            headers={},
            body={"model": "azure_ai/some-partner", "messages": [{"role": "user", "content": "hello"}]},
            user_id=USER,
            policy=policy,
            foundry=_foundry(),
            presidio=client,
            upstream=marketplace,
            audit=audit,
        )
    assert exc.value.code == "azure_ai_disabled"
    assert marketplace.calls == []


def test_egress_default_deny():
    raw = load_destinations(ROOT / "deploy" / "egress-destinations.yaml")
    assert raw["default"] == "deny"
    assert raw["cloudflared_enabled"] is False
    rules = (ROOT / "deploy" / "ufw" / "user.rules").read_text(encoding="utf-8")
    assert "default deny outgoing" in rules
    hosts = []
    for line in rules.splitlines():
        if line.startswith("allow out to "):
            hosts.append(line.split()[3])
    listed = set()
    for item in raw["destinations"]:
        if item.get("enabled", True) is False:
            continue
        listed.update(item.get("hosts") or [])
    assert set(hosts) <= listed
    assert "region1.v2.argotunnel.com" not in hosts
    assert "api.anthropic.com" not in hosts
    assert "pypi.org" not in hosts
    assert "huggingface.co" not in hosts
    assert "login.microsoftonline.com" in hosts
    assert "docker.io" not in rules
    from scripts.egress_owners import render_owner_rules, render_user_rules

    baa_rules = render_user_rules(raw, {"ANTHROPIC_BAA_ENABLED": "true"})
    assert "api.anthropic.com" in baa_rules
    install_rules = render_user_rules(raw, {"INSTALL_EGRESS": "1"})
    assert "pypi.org" in install_rules
    owner = render_owner_rules(raw, {"api.anthropic.com": ["192.0.2.10"]}, {"ANTHROPIC_BAA_ENABLED": "true"})
    assert "--uid-owner litellm" in owner
    assert "192.0.2.10" in owner
    assert "127.0.0.2" in owner
    assert owner.index("openwebui") < owner.index("-o lo -j ACCEPT")
    assert "--uid-owner policy-gateway -j REJECT" in owner
    opened = render_owner_rules(raw, {"mcp.example": ["192.0.2.20"]}, {"STACKJACK_MCP_HOST": "mcp.example"})
    assert "policy-gateway -j REJECT" not in opened
    assert "--uid-owner policy-gateway" in opened


def test_gateway_forwards_litellm_names_and_masks_fields(policy, presidio_services, audit):
    client, _, _ = presidio_services
    result, upstream = _chat("anthropic", policy, client, audit)
    assert result.status == 200
    assert upstream.calls[0]["model"] == "claude-sonnet"
    assert upstream.team_ids == ["phi"]
    hidden, upstream = _chat(
        "azure",
        policy,
        client,
        audit,
        body={
            "model": "azure/dep-placeholder",
            "messages": [{"role": "user", "content": "hello", "_mock_note": "MRN-SYN-0001234"}],
        },
    )
    assert hidden.status == 200
    assert "MRN-SYN-0001234" not in str(upstream.calls[0])
    result, upstream = _chat(
        "azure",
        policy,
        client,
        audit,
        body={
            "model": "foundry-gpt",
            "messages": [{"role": "user", "content": "hello", "name": "Testy McFakerson"}],
            "user": "Testy McFakerson",
        },
    )
    assert result.status == 200
    assert upstream.calls[0]["model"] == "foundry-gpt"
    sent = upstream.calls[0]
    assert "Testy McFakerson" not in str(sent)
    assert "<PERSON>" in sent["user"]
    assert "<PERSON>" in sent["messages"][0]["name"]
    denied, blocked = _chat(
        "anthropic",
        policy,
        client,
        audit,
        headers={"X-Entra-App-Roles": "non-phi"},
    )
    assert isinstance(denied, PolicyError)
    assert denied.code == "entra_model_denied"
    assert blocked.calls == []
    with pytest.raises(PolicyError) as exc:
        handle_chat(
            path="/v1/chat/completions",
            headers={"X-Entra-App-Roles": "admin"},
            body={"model": "azure/dep-placeholder", "messages": [{"role": "user", "content": "hello"}]},
            user_id=USER,
            policy=policy,
            foundry=_foundry(),
            presidio=client,
            upstream=Upstream(),
            audit=audit,
        )
    assert exc.value.code == "entra_role_required"


def test_fixture_header_and_docs():
    text = (ROOT / "tests" / "fixtures" / "synthetic.json").read_text(encoding="utf-8")
    assert HEADER in text
    assert '"seed": 4242' in text
    plan = (ROOT / "PLAN.md").read_text(encoding="utf-8")
    security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    for needle in (
        "VPN/LAN only",
        "ANTHROPIC_BAA_ENABLED",
        "zero data retention",
        "azure_ai/",
        "eastus2",
        "mcr.microsoft.com",
        "30 days",
    ):
        assert needle in plan
    for needle in ("72-hour", "30-day", "recall", "ZDR", "seatbelt"):
        assert needle in security or needle.lower() in security.lower() or needle in (ROOT / "docs" / "incident-response.md").read_text(encoding="utf-8")
    incident = (ROOT / "docs" / "incident-response.md").read_text(encoding="utf-8")
    assert "164.402" in incident
    assert "72-hour" in incident
    assert "30-day" in incident
    checklist = (ROOT / "docs" / "deploy-checklist.md").read_text(encoding="utf-8")
    assert "ZDR" in checklist
    assert "abuse-monitoring" in checklist.lower()


def test_recognizers_json_matches_yaml(recognizers):
    document = json.loads((ROOT / "presidio" / "recognizers.json").read_text(encoding="utf-8"))
    assert document == presidio_ad_hoc(recognizers)


def test_break_glass_refuses_argv(tmp_path):
    import os
    import subprocess

    script = ROOT / "deploy" / "break-glass-enable.sh"
    mode = script.stat().st_mode
    assert mode & stat.S_IXUSR
    denied = subprocess.run([str(script), "secret"], check=False, capture_output=True, text=True)
    assert denied.returncode == 2
    missing = subprocess.run([str(script)], check=False, capture_output=True, text=True, env={**os.environ, "BREAK_GLASS_SECRET_FILE": ""})
    assert missing.returncode == 2
    secret = tmp_path / "glass"
    secret.write_text("not-a-login-password", encoding="utf-8")
    secret.chmod(0o600)
    audit = tmp_path / "audit.log"
    env = {**os.environ, "BREAK_GLASS_SECRET_FILE": str(secret), "BREAK_GLASS_AUDIT_LOG": str(audit)}
    closed = subprocess.run([str(script)], check=False, capture_output=True, text=True, env=env)
    assert closed.returncode == 1
    assert "does not enable login" in closed.stderr
    assert "not-a-login-password" not in closed.stdout
    assert "not-a-login-password" not in closed.stderr
    line = audit.read_text(encoding="utf-8")
    assert "password login was not enabled" in line
    assert "not-a-login-password" not in line


def test_install_check_twice():
    import subprocess

    script = ROOT / "deploy" / "install.sh"
    first = subprocess.run([str(script), "--check"], check=False, capture_output=True, text=True)
    second = subprocess.run([str(script), "--check"], check=False, capture_output=True, text=True)
    assert first.returncode == 0, first.stderr
    assert second.returncode == 0, second.stderr
    assert first.stdout == second.stdout
