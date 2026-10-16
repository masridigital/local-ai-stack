"""Per-backend guardrails for Anthropic and Microsoft Foundry.

Anthropic uses the current model ids. The draft's claude-3-opus id is rejected.
Foundry allows azure/ in a US region. azure_ai/ stays off unless the test turns it on.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from stack.errors import PolicyError
from stack.policy import FoundryRuntime
from tests.support.chat import default_foundry, run_chat


def _foundry(**overrides) -> FoundryRuntime:
    current = default_foundry()
    data = {
        "deployment": current.deployment,
        "model_family": current.model_family,
        "region": current.region,
        "api_base": current.api_base,
    }
    data.update(overrides)
    return FoundryRuntime(**data)


@pytest.mark.parametrize(
    ("model", "code"),
    [
        ("anthropic/claude-sonnet-4-5", None),
        ("anthropic/claude-haiku-4-5", None),
        ("anthropic/claude-opus-4-5", None),
        ("anthropic/claude-3-opus-20240229", "model_not_allowlisted"),
        ("anthropic/claude-unknown", "model_not_allowlisted"),
        ("bedrock/claude", "model_not_allowlisted"),
        ("vertex_ai/claude", "model_not_allowlisted"),
        ("gpt-4o", "model_not_allowlisted"),
    ],
)
def test_anthropic_model_allowlist(model, code, policy, presidio_services, audit):
    client, _analyzer, _anonymizer = presidio_services
    opened = replace(policy, anthropic_baa_enabled=True)
    result, upstream = run_chat("anthropic", opened, client, audit, body={"model": model})
    if code is None:
        assert getattr(result, "status", None) == 200
        assert result.backend == "anthropic"
        assert upstream.calls[0]["model"] == model
        return
    assert isinstance(result, PolicyError)
    assert result.code == code
    assert upstream.calls == []


def test_anthropic_blocked_when_baa_is_off(policy, presidio_services, audit):
    client, _analyzer, _anonymizer = presidio_services
    assert policy.anthropic_baa_enabled is False
    result, upstream = run_chat("anthropic", policy, client, audit)
    assert isinstance(result, PolicyError)
    assert result.code == "anthropic_baa_disabled"
    assert upstream.calls == []


@pytest.mark.parametrize(
    ("model", "foundry_kwargs", "code"),
    [
        ("azure/dep-placeholder", {}, None),
        ("azure/other-dep", {}, "deployment_not_allowed"),
        ("azure/dep-placeholder", {"region": "westeurope"}, "region_not_allowed"),
        ("azure/dep-placeholder", {"model_family": "gpt-35-turbo"}, "model_family_not_allowed"),
        ("azure/dep-placeholder", {"api_base": "https://example.com/"}, "api_base_not_azure_openai"),
        (
            "azure/dep-placeholder",
            {"api_base": "https://westeurope.openai.azure.com/", "region": "eastus2"},
            "region_not_allowed",
        ),
        (
            "azure/dep-placeholder",
            {"api_base": "https://cap-westus3.openai.azure.com/", "region": "eastus2"},
            "region_mismatch",
        ),
        ("azure_ai/partner-model", {}, "azure_ai_disabled"),
    ],
)
def test_foundry_allowlist(model, foundry_kwargs, code, policy, presidio_services, audit):
    client, _analyzer, _anonymizer = presidio_services
    backend = "azure_ai" if model.startswith("azure_ai/") else "azure"
    result, upstream = run_chat(
        backend,
        policy,
        client,
        audit,
        body={"model": model},
        foundry=_foundry(**foundry_kwargs),
    )
    if code is None:
        assert result.status == 200
        assert result.backend == "azure"
        assert "abuse" not in upstream.calls[0]
        return
    assert isinstance(result, PolicyError)
    assert result.code == code
    assert upstream.calls == []


def test_azure_ai_requires_a_us_region_when_enabled(policy, presidio_services, audit):
    client, _analyzer, _anonymizer = presidio_services
    opened = replace(policy, foundry=replace(policy.foundry, azure_ai_enabled=True))
    blocked, upstream = run_chat(
        "azure_ai",
        opened,
        client,
        audit,
        foundry=_foundry(region="westeurope"),
    )
    assert isinstance(blocked, PolicyError)
    assert blocked.code == "region_not_allowed"
    assert upstream.calls == []
    allowed, called = run_chat("azure_ai", opened, client, audit)
    assert allowed.status == 200
    assert allowed.backend == "azure_ai"
    assert called.calls


def test_foundry_defaults_stay_off(policy):
    assert policy.foundry.azure_ai_enabled is False
    assert policy.foundry.abuse_monitoring_opt_out is False
    assert "eastus2" in policy.foundry.allowed_regions
    assert "westus3" in policy.foundry.allowed_regions
    assert "westeurope" not in policy.foundry.allowed_regions
    assert "gpt-4.1" in policy.foundry.allowed_model_families
    assert "gpt-4o" in policy.foundry.allowed_model_families
