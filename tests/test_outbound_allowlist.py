"""Default-deny outbound allowlist. Optional MCP hosts stay closed."""

from __future__ import annotations

from pathlib import Path

from scripts.egress_owners import render_owner_rules, render_user_rules
from stack.egress import host_allowed, load_destinations

ROOT = Path(__file__).resolve().parents[1]


def _destinations():
    return load_destinations(ROOT / "deploy" / "egress-destinations.yaml")


def test_default_deny_and_rules_match_the_list():
    raw = _destinations()
    assert raw["default"] == "deny"
    assert raw["cloudflared_enabled"] is False
    user_rules = (ROOT / "deploy" / "ufw" / "user.rules").read_text(encoding="utf-8")
    owner_rules = (ROOT / "deploy" / "ufw" / "owner.rules").read_text(encoding="utf-8")
    assert user_rules == render_user_rules(raw)
    assert owner_rules == render_owner_rules(raw, {})
    assert "default deny incoming" in user_rules
    assert "default deny outgoing" in user_rules
    assert "0.0.0.0" not in user_rules
    assert "*" not in user_rules
    assert "docker.io" not in user_rules
    assert "argotunnel" not in user_rules
    assert "api.anthropic.com" in user_rules
    assert "login.microsoftonline.com" in user_rules
    for item in raw["destinations"]:
        for host in item.get("hosts") or []:
            assert "*" not in host
            assert host != "0.0.0.0"


def test_static_allows_and_denies():
    raw = _destinations()
    assert host_allowed("api.anthropic.com", raw, {})
    assert host_allowed("login.microsoftonline.com", raw, {})
    assert host_allowed("pypi.org", raw, {})
    assert not host_allowed("region1.v2.argotunnel.com", raw, {})
    assert not host_allowed("cloudflare.com", raw, {})
    assert not host_allowed("evil.example", raw, {})
    assert not host_allowed("mcp.stackjack.example", raw, {})
    assert not host_allowed("api.composio.dev", raw, {})
    azure_env = {"AZURE_API_HOST": "cap-eastus2.openai.azure.com"}
    assert host_allowed("cap-eastus2.openai.azure.com", raw, azure_env)
    assert not host_allowed("other.openai.azure.com", raw, azure_env)
    assert not host_allowed("evil.example", raw, {"AZURE_API_HOST": "evil.example"})


def test_optional_upstreams_are_closed_until_configured():
    raw = _destinations()
    by_name = {item["name"]: item for item in raw["destinations"]}
    for name in ("stackjack", "composio", "azure-openai", "siem", "dns"):
        assert by_name[name]["optional"] is True
        assert "hosts" not in by_name[name] or not by_name[name].get("hosts")
    user_rules = (ROOT / "deploy" / "ufw" / "user.rules").read_text(encoding="utf-8")
    assert "policy-gateway" not in user_rules
    owner = render_owner_rules(raw, {})
    assert "--uid-owner policy-gateway -j REJECT" in owner
    assert "--uid-owner presidio-analyzer -j REJECT" in owner
    assert "--uid-owner cloudflared -j REJECT" in owner
    opened = render_owner_rules(raw, {"mcp.example": ["192.0.2.20"]}, {"STACKJACK_MCP_HOST": "mcp.example"})
    assert "--uid-owner policy-gateway -d 192.0.2.20" in opened
    assert "policy-gateway -j REJECT" not in opened
    litellm = render_owner_rules(raw, {"api.anthropic.com": ["192.0.2.10"]})
    assert "--uid-owner litellm -d 192.0.2.10" in litellm
    assert "--uid-owner openwebui -d 192.0.2.10" not in litellm
