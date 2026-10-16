"""Chat and MCP request pipeline. Presidio failure blocks the upstream call."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field

from stack.audit import AuditLog
from stack.errors import PolicyError, PresidioUnavailable
from stack.policy import (
    FoundryRuntime,
    Policy,
    blocked_header,
    blocked_tools,
    classify_model,
    resolve_entra_team,
    resolve_model,
    unexpected_params,
)
from stack.presidio_client import PresidioClient


def _test_mode() -> bool:
    return os.environ.get("LOCAL_AI_TEST_MODE", "").lower() in {"1", "true"}


@dataclass
class Upstream:
    calls: list[dict] = field(default_factory=list)
    team_ids: list[str | None] = field(default_factory=list)

    def complete(self, payload: dict, team_id: str | None = None) -> dict:
        payload = dict(payload)
        content = payload.pop("_mock_response", None)
        self.calls.append(payload)
        self.team_ids.append(team_id)
        if content is None:
            content = "synthetic ok"
        return {
            "id": "cmpl-synthetic",
            "object": "chat.completion",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": "stop"}],
        }


@dataclass
class McpUpstream:
    calls: list[dict] = field(default_factory=list)

    def call(self, server: str, tool: str, arguments: dict) -> dict:
        self.calls.append({"server": server, "tool": tool, "arguments": arguments})
        return {"result": arguments.get("_mock_result", "synthetic tool ok")}


@dataclass
class ChatResult:
    status: int
    body: dict
    backend: str | None = None


def handle_chat(
    *,
    path: str,
    headers: dict[str, str],
    body: dict,
    user_id: str | None,
    policy: Policy,
    foundry: FoundryRuntime,
    presidio: PresidioClient,
    upstream: Upstream,
    audit: AuditLog,
    mock_response: str | None = None,
) -> ChatResult:
    route = _normalize(path)
    if route not in {"/v1/chat/completions", "/chat/completions"}:
        audit.write(event_type="request", decision="block", user_id=user_id, route=route, reason="route_disabled")
        raise PolicyError("route_disabled", "route is not enabled")
    if not user_id:
        audit.write(event_type="request", decision="block", route=route, reason="user_identity_required")
        raise PolicyError("user_identity_required", "Entra user id is required")
    header = blocked_header(headers, policy)
    if header:
        audit.write(
            event_type="request",
            decision="block",
            user_id=user_id,
            route=route,
            reason="beta_header_blocked",
        )
        raise PolicyError("beta_header_blocked", "beta or blocked header rejected")
    if body.get("stream") is True or policy.streaming_enabled:
        audit.write(
            event_type="request",
            decision="block",
            user_id=user_id,
            route=route,
            reason="streaming_disabled",
        )
        raise PolicyError("streaming_disabled", "streaming is disabled until chunk masking is proven")
    if "tools" in body or "tool_choice" in body or blocked_tools(body, policy):
        audit.write(event_type="request", decision="block", user_id=user_id, route=route, reason="tool_blocked")
        raise PolicyError("tool_blocked", "server-side tools and tool calls are blocked")
    extras = unexpected_params(body, policy)
    if extras:
        audit.write(event_type="request", decision="block", user_id=user_id, route=route, reason="param_not_allowlisted")
        raise PolicyError("param_not_allowlisted", "request contains parameters outside the allowlist")
    model = body.get("model")
    if not isinstance(model, str):
        raise PolicyError("model_not_allowlisted", "model is required")
    litellm_model, provider_model = resolve_model(model, policy, foundry)
    try:
        backend = classify_model(provider_model, policy, foundry)
        team_id = resolve_entra_team(headers, litellm_model, provider_model, policy)
    except PolicyError as exc:
        audit.write(
            event_type="request",
            decision="block",
            user_id=user_id,
            route=route,
            model=litellm_model,
            reason=exc.code,
        )
        raise
    messages = body.get("messages")
    if not isinstance(messages, list) or not messages:
        raise PolicyError("invalid_messages", "messages must be a non-empty list")
    try:
        masked_messages, entities = _mask_messages(messages, presidio)
    except (PresidioUnavailable, PolicyError) as exc:
        audit.write(
            event_type="request",
            decision="block",
            user_id=user_id,
            route=route,
            backend=backend,
            model=model,
            reason=getattr(exc, "code", "presidio_unavailable"),
        )
        raise
    forward = {
        "model": litellm_model,
        "messages": masked_messages,
        "stream": False,
    }
    for key in ("max_tokens", "temperature", "top_p", "stop"):
        if key in body:
            forward[key] = body[key]
    if "user" in body:
        masked_user, found = _mask_obj(body["user"], presidio)
        forward["user"] = masked_user
        entities.extend(found)
    if mock_response is not None:
        forward["_mock_response"] = mock_response
    # Abuse-monitoring opt-out is not sent. Cap has not asked us to assume it.
    raw = upstream.complete(
        {key: value for key, value in forward.items() if key == "_mock_response" or not key.startswith("_")},
        team_id=team_id or None,
    )
    content = _assistant_text(raw)
    try:
        masked_content, response_entities = presidio.mask_text(content)
    except (PresidioUnavailable, PolicyError) as exc:
        audit.write(
            event_type="request",
            decision="block",
            user_id=user_id,
            route=route,
            backend=backend,
            model=model,
            reason=getattr(exc, "code", "presidio_unavailable"),
            entity_types=entities,
            prompt_redacted=_join_content(masked_messages),
        )
        raise PolicyError("presidio_unavailable", "response blocked because post-call masking failed", status=503) from exc
    prompt_redacted = _join_content(masked_messages)
    audit.write(
        event_type="request",
        decision="allow",
        user_id=user_id,
        route=route,
        backend=backend,
        model=model,
        entity_types=sorted(set(entities + response_entities)),
        prompt_redacted=prompt_redacted,
        response_redacted=masked_content,
    )
    raw["choices"][0]["message"]["content"] = masked_content
    raw.pop("usage", None)
    return ChatResult(status=200, body=raw, backend=backend)


def handle_mcp(
    *,
    server: str,
    tool: str,
    arguments: dict,
    user_id: str | None,
    policy: Policy,
    presidio: PresidioClient,
    upstream: McpUpstream,
    audit: AuditLog,
) -> dict:
    if not user_id:
        raise PolicyError("user_identity_required", "Entra user id is required")
    mock_result = None
    if isinstance(arguments, dict):
        arguments = dict(arguments)
        if "_mock_result" in arguments:
            if not _test_mode():
                audit.write(event_type="mcp", decision="block", user_id=user_id, route="/mcp", reason="mock_disabled")
                raise PolicyError("mock_disabled", "mock results are test-only")
            mock_result = arguments.pop("_mock_result")
    match = _mcp_server(server, policy)
    if match is None:
        audit.write(event_type="mcp", decision="block", user_id=user_id, route="/mcp", reason="mcp_not_allowlisted")
        raise PolicyError("mcp_not_allowlisted", "MCP upstream is not allowlisted")
    if tool != match.get("tool") or "*" in tool or not tool:
        audit.write(event_type="mcp", decision="block", user_id=user_id, route="/mcp", reason="mcp_tool_wildcard")
        raise PolicyError("mcp_tool_wildcard", "MCP tool must be an explicit id")
    try:
        masked_args, entities = _mask_obj(arguments, presidio)
    except (PresidioUnavailable, PolicyError) as exc:
        audit.write(event_type="mcp", decision="block", user_id=user_id, route="/mcp", reason=getattr(exc, "code", "presidio_unavailable"))
        raise
    result = upstream.call(server, tool, masked_args)
    if mock_result is not None:
        result = {"result": mock_result}
    try:
        masked_result, result_entities = _mask_obj(result, presidio)
    except (PresidioUnavailable, PolicyError) as exc:
        audit.write(event_type="mcp", decision="block", user_id=user_id, route="/mcp", reason="presidio_unavailable", entity_types=entities)
        raise PolicyError("presidio_unavailable", "mcp result blocked", status=503) from exc
    audit.write(
        event_type="mcp",
        decision="allow",
        user_id=user_id,
        route="/mcp",
        backend=match["kind"],
        model=tool,
        entity_types=sorted(set(entities + result_entities)),
        prompt_redacted=json.dumps(masked_args, sort_keys=True),
        response_redacted=json.dumps(masked_result, sort_keys=True),
    )
    return masked_result


def record_config_change(audit: AuditLog, policy: Policy, actor: str, policy_bytes: bytes) -> dict:
    digest = hashlib.sha256(policy_bytes).hexdigest()
    return audit.write(
        event_type="config_change",
        decision="recorded",
        user_id=actor,
        reason="policy_load",
        config_hash=digest,
    )


def _mcp_server(server: str, policy: Policy) -> dict | None:
    for item in policy.mcp_allowed_upstreams:
        if item.get("server") == server and item.get("kind") in policy.mcp_allowed_kinds:
            if "*" in server or item.get("tool", "").find("*") >= 0:
                return None
            return item
    return None


def _mask_messages(messages: list, presidio: PresidioClient) -> tuple[list, list[str]]:
    masked = []
    entities: list[str] = []
    for message in messages:
        if not isinstance(message, dict):
            raise PolicyError("invalid_messages", "message must be an object")
        content = message.get("content")
        new_message = dict(message)
        if isinstance(content, str):
            text, found = presidio.mask_text(content)
            new_message["content"] = text
            entities.extend(found)
        elif isinstance(content, list):
            parts = []
            for part in content:
                if not isinstance(part, dict) or part.get("type") != "text" or not isinstance(part.get("text"), str):
                    raise PolicyError("non_text_blocked", "non-text content is blocked")
                text, found = presidio.mask_text(part["text"])
                parts.append({"type": "text", "text": text})
                entities.extend(found)
            new_message["content"] = parts
        else:
            raise PolicyError("non_text_blocked", "message content must be text")
        for key, value in list(new_message.items()):
            if key in {"role", "content"}:
                continue
            masked_value, found = _mask_obj(value, presidio)
            new_message[key] = masked_value
            entities.extend(found)
        masked.append(new_message)
    return masked, entities


def _mask_obj(value, presidio: PresidioClient):
    if isinstance(value, str):
        return presidio.mask_text(value)
    if isinstance(value, dict):
        masked = {}
        entities: list[str] = []
        for key, item in value.items():
            if not isinstance(key, str):
                raise PolicyError("non_text_blocked", "non-text object key")
            new_item, found = _mask_obj(item, presidio)
            masked[key] = new_item
            entities.extend(found)
        return masked, entities
    if isinstance(value, list):
        items = []
        entities = []
        for item in value:
            new_item, found = _mask_obj(item, presidio)
            items.append(new_item)
            entities.extend(found)
        return items, entities
    if value is None or isinstance(value, (int, float, bool)):
        return value, []
    raise PolicyError("non_text_blocked", "unsupported JSON value")


def _assistant_text(raw: dict) -> str:
    try:
        content = raw["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise PolicyError("upstream_invalid", "upstream response has no assistant text", status=502) from exc
    if not isinstance(content, str):
        raise PolicyError("non_text_blocked", "upstream content is not text", status=502)
    return content


def _join_content(messages: list) -> str:
    parts = []
    for message in messages:
        content = message.get("content")
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, list):
            parts.extend(part.get("text", "") for part in content)
    return "\n".join(parts)


def _normalize(path: str) -> str:
    if path != "/" and path.endswith("/"):
        return path[:-1]
    return path
