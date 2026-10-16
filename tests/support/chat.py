"""Shared chat helpers for the native gateway tests."""

from __future__ import annotations

from pathlib import Path

from stack.errors import PolicyError
from stack.pipeline import Upstream, handle_chat
from stack.policy import FoundryRuntime

ROOT = Path(__file__).resolve().parents[2]
USER = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def default_foundry() -> FoundryRuntime:
    return FoundryRuntime(
        deployment="dep-placeholder",
        model_family="gpt-4.1",
        region="eastus2",
        api_base="https://cap-eastus2.openai.azure.com/",
    )


def model_for(backend: str) -> str:
    if backend == "anthropic":
        return "anthropic/claude-sonnet-4-5"
    if backend == "azure":
        return "azure/dep-placeholder"
    if backend == "azure_ai":
        return "azure_ai/marketplace-fixture"
    raise AssertionError(backend)


def run_chat(
    backend: str,
    policy,
    presidio,
    audit,
    *,
    body: dict | None = None,
    headers: dict | None = None,
    path: str = "/v1/chat/completions",
    user_id: str | None = USER,
    foundry: FoundryRuntime | None = None,
    mock_response: str | None = None,
):
    """Call the gateway. Returns the ChatResult or the PolicyError, plus the mock upstream."""
    upstream = Upstream()
    payload = {
        "model": model_for(backend),
        "messages": [{"role": "user", "content": "hello"}],
        "max_tokens": 16,
    }
    if body:
        payload.update(body)
    try:
        result = handle_chat(
            path=path,
            headers=headers or {},
            body=payload,
            user_id=user_id,
            policy=policy,
            foundry=foundry or default_foundry(),
            presidio=presidio,
            upstream=upstream,
            audit=audit,
            mock_response=mock_response,
        )
    except PolicyError as exc:
        return exc, upstream
    return result, upstream
