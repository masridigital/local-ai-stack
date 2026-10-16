"""Allowlists loaded from litellm/policy.yaml, with runtime switches from the environment."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass(frozen=True)
class FoundryPolicy:
    azure_ai_enabled: bool
    allowed_model_families: frozenset[str]
    allowed_regions: frozenset[str]
    abuse_monitoring_opt_out: bool


@dataclass(frozen=True)
class Policy:
    mask_score_threshold: float
    streaming_enabled: bool
    anthropic_baa_enabled: bool
    anthropic_zdr_confirmed_by_cap: bool
    anthropic_allowed_models: frozenset[str]
    anthropic_allowed_params: frozenset[str]
    blocked_header_names: frozenset[str]
    blocked_header_prefixes: tuple[str, ...]
    blocked_tool_types: frozenset[str]
    enabled_routes: frozenset[str]
    foundry: FoundryPolicy
    mcp_allowed_upstreams: tuple[dict, ...]
    mcp_allowed_kinds: frozenset[str]
    recall_floors: dict[str, float]
    chat_retention_days: int
    audit_review: dict


# Longer names first so "eastus" does not swallow "eastus2".
_NON_US_REGION_TOKENS = (
    "germanywestcentral",
    "australiasoutheast",
    "switzerlandnorth",
    "francecentral",
    "swedencentral",
    "norwayeast",
    "polandcentral",
    "italynorth",
    "spaincentral",
    "westeurope",
    "northeurope",
    "southeastasia",
    "southafricanorth",
    "canadacentral",
    "canadaeast",
    "brazilsouth",
    "uksouth",
    "ukwest",
    "eastasia",
    "japaneast",
    "japanwest",
    "koreacentral",
    "centralindia",
    "southindia",
    "uaenorth",
    "qatarcentral",
    "israelcentral",
    "mexicocentral",
    "australiaeast",
)


def load_policy(path: Path, runtime: dict | None = None) -> Policy:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    runtime = runtime or {}
    foundry_raw = raw["foundry"]
    azure_ai = bool(foundry_raw["azure_ai_enabled"])
    if "azure_ai_enabled" in runtime:
        azure_ai = bool(runtime["azure_ai_enabled"])
    baa = bool(raw["anthropic_baa_enabled"])
    if "anthropic_baa_enabled" in runtime:
        baa = bool(runtime["anthropic_baa_enabled"])
    abuse = bool(foundry_raw["abuse_monitoring_opt_out"])
    if "abuse_monitoring_opt_out" in runtime:
        abuse = bool(runtime["abuse_monitoring_opt_out"])
    foundry = FoundryPolicy(
        azure_ai_enabled=azure_ai,
        allowed_model_families=frozenset(foundry_raw["allowed_model_families"]),
        allowed_regions=frozenset(foundry_raw["allowed_regions"]),
        abuse_monitoring_opt_out=abuse,
    )
    return Policy(
        mask_score_threshold=float(raw["mask_score_threshold"]),
        streaming_enabled=bool(raw["streaming_enabled"]),
        anthropic_baa_enabled=baa,
        anthropic_zdr_confirmed_by_cap=bool(raw["anthropic_zdr_confirmed_by_cap"]),
        anthropic_allowed_models=frozenset(raw["anthropic_allowed_models"]),
        anthropic_allowed_params=frozenset(raw["anthropic_allowed_params"]),
        blocked_header_names=frozenset(h.lower() for h in raw["blocked_header_names"]),
        blocked_header_prefixes=tuple(p.lower() for p in raw["blocked_header_prefixes"]),
        blocked_tool_types=frozenset(raw["blocked_tool_types"]),
        enabled_routes=frozenset(raw["enabled_routes"]),
        foundry=foundry,
        mcp_allowed_upstreams=tuple(raw["mcp"]["allowed_upstreams"]),
        mcp_allowed_kinds=frozenset(raw["mcp"]["allowed_kinds"]),
        recall_floors={k: float(v) for k, v in raw["recall_floors"].items()},
        chat_retention_days=int(raw["chat_retention_days"]),
        audit_review=dict(raw["audit_review"]),
    )


@dataclass(frozen=True)
class FoundryRuntime:
    deployment: str
    model_family: str
    region: str
    api_base: str


def classify_model(model: str, policy: Policy, foundry: FoundryRuntime) -> str:
    from stack.errors import PolicyError

    if model.startswith("anthropic/"):
        if not policy.anthropic_baa_enabled:
            raise PolicyError(
                "anthropic_baa_disabled",
                "Anthropic BAA switch is off; calls are blocked until the deploy checklist is signed",
            )
        if model not in policy.anthropic_allowed_models:
            raise PolicyError("model_not_allowlisted", "model is outside the Anthropic allowlist")
        return "anthropic"
    if model.startswith("azure_ai/"):
        if not policy.foundry.azure_ai_enabled:
            raise PolicyError(
                "azure_ai_disabled",
                "azure_ai marketplace models are disabled; they may fall outside Microsoft's BAA",
            )
        _require_us_region(foundry.region, policy)
        return "azure_ai"
    if model.startswith("azure/"):
        deployment = model.split("/", 1)[1]
        if not foundry.deployment or deployment != foundry.deployment:
            raise PolicyError("deployment_not_allowed", "Azure deployment is not the configured placeholder")
        if foundry.model_family not in policy.foundry.allowed_model_families:
            raise PolicyError(
                "model_family_not_allowed",
                "only Microsoft first-party gpt-4.1 and gpt-4o families are allowed",
            )
        _require_us_region(foundry.region, policy)
        _check_api_base(foundry.api_base, foundry.region, policy)
        return "azure"
    if model.startswith("bedrock/") or model.startswith("vertex_ai/") or model.startswith("vertex/"):
        raise PolicyError("model_not_allowlisted", "Bedrock and Vertex are not backends on this stack")
    raise PolicyError("model_not_allowlisted", "model is outside the Anthropic and Foundry allowlist")


def _require_us_region(region: str, policy: Policy) -> None:
    from stack.errors import PolicyError

    if region not in policy.foundry.allowed_regions:
        raise PolicyError("region_not_allowed", "Foundry region must be a US region")


def _check_api_base(api_base: str, region: str, policy: Policy) -> None:
    from stack.errors import PolicyError

    host = api_base.lower().split("://", 1)[-1].split("/", 1)[0]
    if not host.endswith(".openai.azure.com"):
        raise PolicyError("api_base_not_azure_openai", "Azure OpenAI API base must be a *.openai.azure.com host")
    for token in _NON_US_REGION_TOKENS:
        if token in host:
            raise PolicyError("region_not_allowed", "API host names a non-US region")
    found = _us_regions_in_host(host, policy.foundry.allowed_regions)
    if found and region not in found:
        raise PolicyError("region_mismatch", "API host region does not match AZURE_OPENAI_REGION")


def _us_regions_in_host(host: str, allowed: frozenset[str]) -> list[str]:
    remaining = host
    found: list[str] = []
    for region in sorted(allowed, key=len, reverse=True):
        if region in remaining:
            found.append(region)
            remaining = remaining.replace(region, "")
    return found


def blocked_header(headers: dict[str, str], policy: Policy) -> str | None:
    for key in headers:
        lowered = key.lower()
        if lowered in policy.blocked_header_names:
            return lowered
        for prefix in policy.blocked_header_prefixes:
            if lowered.startswith(prefix):
                return lowered
    return None


def unexpected_params(body: dict, policy: Policy) -> list[str]:
    allowed = set(policy.anthropic_allowed_params) | {"stream"}
    return sorted(set(body) - allowed)


def blocked_tools(body: dict, policy: Policy) -> list[str]:
    tools = body.get("tools") or []
    found: list[str] = []
    if not isinstance(tools, list):
        return ["tools"]
    for tool in tools:
        if not isinstance(tool, dict):
            found.append("unknown")
            continue
        kind = str(tool.get("type") or tool.get("name") or "")
        if kind in policy.blocked_tool_types or kind.startswith("computer"):
            found.append(kind)
    return found
