"""Anthropic BAA switch defaults off. Beta, files, batches, and web stay blocked."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from stack.errors import PolicyError
from stack.server import build_deps
from tests.support.chat import run_chat

ROOT = Path(__file__).resolve().parents[1]


def test_policy_file_defaults_off(policy):
    assert policy.anthropic_baa_enabled is False
    assert policy.streaming_enabled is False
    assert policy.anthropic_zdr_confirmed_by_cap is True
    assert "anthropic-beta" in policy.blocked_header_names
    for kind in ("web_search", "web_fetch", "code_execution", "computer", "files"):
        assert kind in policy.blocked_tool_types
    for path in ("/v1/files", "/v1/batches", "/v1/messages"):
        assert path not in policy.enabled_routes
    assert "/v1/chat/completions" in policy.enabled_routes


def test_process_env_defaults_off(tmp_path, monkeypatch, policy):
    monkeypatch.delenv("ANTHROPIC_BAA_ENABLED", raising=False)
    monkeypatch.setenv("POLICY_PATH", str(ROOT / "litellm" / "policy.yaml"))
    monkeypatch.setenv("RECOGNIZER_DIR", str(ROOT / "presidio" / "recognizers"))
    monkeypatch.setenv("AUDIT_SQLITE_PATH", str(tmp_path / "audit.db"))
    monkeypatch.setenv("PRESIDIO_ANALYZER_API_BASE", "http://127.0.0.1:9")
    monkeypatch.setenv("PRESIDIO_ANONYMIZER_API_BASE", "http://127.0.0.1:9")
    loaded, _foundry, _presidio, _audit = build_deps()
    assert loaded.anthropic_baa_enabled is False
    assert loaded.foundry.azure_ai_enabled is False
    assert policy.anthropic_baa_enabled is False


def test_default_blocks_a_clean_anthropic_chat(policy, presidio_services, audit):
    client, _analyzer, _anonymizer = presidio_services
    result, upstream = run_chat(
        "anthropic",
        policy,
        client,
        audit,
        body={"messages": [{"role": "user", "content": "hello"}]},
    )
    assert isinstance(result, PolicyError)
    assert result.code == "anthropic_baa_disabled"
    assert result.status == 403
    assert upstream.calls == []


@pytest.mark.parametrize(
    "headers",
    [
        {"anthropic-beta": "computer-use-2025-01-24"},
        {"Anthropic-Beta": "files-api-2025-04-14"},
        {"anthropic-beta-files": "1"},
    ],
)
@pytest.mark.parametrize("baa_on", [False, True])
def test_beta_header_blocked_regardless_of_baa(headers, baa_on, policy, presidio_services, audit):
    client, _analyzer, _anonymizer = presidio_services
    active = replace(policy, anthropic_baa_enabled=baa_on)
    result, upstream = run_chat("anthropic", active, client, audit, headers=headers)
    assert isinstance(result, PolicyError)
    assert result.code == "beta_header_blocked"
    assert upstream.calls == []


@pytest.mark.parametrize("path", ["/v1/files", "/v1/batches", "/v1/messages"])
@pytest.mark.parametrize("baa_on", [False, True])
def test_files_batches_and_messages_routes_blocked(path, baa_on, policy, presidio_services, audit):
    client, _analyzer, _anonymizer = presidio_services
    active = replace(policy, anthropic_baa_enabled=baa_on)
    result, upstream = run_chat("anthropic", active, client, audit, path=path)
    assert isinstance(result, PolicyError)
    assert result.code == "route_disabled"
    assert upstream.calls == []


@pytest.mark.parametrize(
    "tool_type",
    ["web_search", "web_fetch", "code_execution", "computer", "computer_20250124", "bash", "text_editor"],
)
@pytest.mark.parametrize("baa_on", [False, True])
def test_web_and_server_tools_blocked(tool_type, baa_on, policy, presidio_services, audit):
    client, _analyzer, _anonymizer = presidio_services
    active = replace(policy, anthropic_baa_enabled=baa_on)
    result, upstream = run_chat(
        "anthropic",
        active,
        client,
        audit,
        body={"tools": [{"type": tool_type}]},
    )
    assert isinstance(result, PolicyError)
    assert result.code == "tool_blocked"
    assert upstream.calls == []


def test_open_webui_disables_web_and_uploads():
    env = (ROOT / "deploy" / "env" / "open-webui.env").read_text(encoding="utf-8")
    for line in (
        "ENABLE_WEB_SEARCH=false",
        "ENABLE_RAG_WEB_SEARCH=false",
        "ENABLE_RAG_LOCAL_WEB_FETCH=false",
        "USER_PERMISSIONS_CHAT_FILE_UPLOAD=false",
        "USER_PERMISSIONS_CHAT_WEB_UPLOAD=false",
        "ENABLE_CODE_INTERPRETER=false",
    ):
        assert line in env
    config = (ROOT / "litellm" / "config.yaml").read_text(encoding="utf-8")
    assert "web_search" not in config
    assert "store_prompts_in_spend_logs: false" in config
