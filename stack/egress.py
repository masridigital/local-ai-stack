"""Default-deny egress list. Destinations are explicit; nothing else is allowed."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

# Served by the runtime forward proxy. Everything else stays off that proxy.
RUNTIME_PROXY_USERS = ("openwebui", "litellm")
# Apt, package hosts, SIEM, and MCP are direct skuid rules, not proxy destinations.
RUNTIME_PROXY_EXCLUDED = frozenset(
    {
        "ubuntu-updates",
        "pypi",
        "caddy-apt",
        "cloudflared-apt",
        "spacy-model",
        "embedding-model",
        "ntp",
        "dns",
        "siem",
        "stackjack",
        "composio",
        "cloudflared",
    }
)
AZURE_SUFFIX = ".openai.azure.com"


def load_destinations(path: Path) -> dict:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if raw.get("default") != "deny":
        raise ValueError("egress default must be deny")
    return raw


def destination_active(item: dict, env: dict[str, str]) -> bool:
    """A row is live only when its flag, optional host, and install-time gate say so."""
    if item.get("enabled", True) is False:
        return False
    if item.get("install_only") and env.get("INSTALL_EGRESS", "") != "1":
        return False
    if item.get("optional") and item.get("env"):
        value = env.get(item["env"], "")
        expected = item.get("env_value")
        if expected is not None:
            return value == expected
        return bool(value)
    return True


def allowed_hosts(raw: dict, env: dict[str, str]) -> list[str]:
    hosts: list[str] = []
    for item in raw["destinations"]:
        if not destination_active(item, env):
            continue
        hosts.extend(item.get("hosts") or [])
        if item.get("env_value"):
            continue
        env_name = item.get("env")
        if env_name and env.get(env_name):
            hosts.append(env[env_name])
    return hosts


def us_regions(policy_path: Path | None = None) -> tuple[str, ...]:
    path = policy_path or Path(__file__).resolve().parents[1] / "litellm" / "policy.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    return tuple(document["foundry"]["allowed_regions"])


def azure_host_ok(host: str, regions: tuple[str, ...] | None = None) -> bool:
    """One label, no dot-dot, and a US region token from the Foundry allowlist."""
    name = host.strip().lower().rstrip(".")
    if not name or ".." in name or not name.endswith(AZURE_SUFFIX):
        return False
    label = name[: -len(AZURE_SUFFIX)]
    if "." in label or not re.fullmatch(r"[a-z0-9-]+", label):
        return False
    allowed = regions if regions is not None else us_regions()
    return any(part in allowed for part in label.split("-"))


def _row_matches(host: str, item: dict, env: dict[str, str]) -> bool:
    for listed in item.get("hosts") or []:
        if host == listed.lower():
            return True
    if item.get("env_value"):
        return False
    env_name = item.get("env")
    configured = env.get(env_name, "").strip().lower().rstrip(".") if env_name else ""
    if not configured or host != configured:
        return False
    if item.get("name") == "azure-openai" or item.get("host_suffix") == AZURE_SUFFIX:
        return azure_host_ok(configured)
    suffix = item.get("host_suffix")
    if suffix and not host.endswith(suffix.lower()):
        return False
    return True


def host_allowed(host: str, raw: dict, env: dict[str, str], user: str | None = None) -> bool:
    """Active row match. Pass user to require that row's users list."""
    host = host.lower().rstrip(".")
    for item in raw["destinations"]:
        if not destination_active(item, env):
            continue
        if user is not None and user not in item.get("users", []):
            continue
        if _row_matches(host, item, env):
            return True
    return False


def proxy_host_allowed(host: str, user: str, raw: dict, env: dict[str, str]) -> bool:
    """Runtime proxy allowlist for one service. Apt, SIEM, and MCP are excluded."""
    if user not in RUNTIME_PROXY_USERS:
        return False
    host = host.lower().rstrip(".")
    for item in raw["destinations"]:
        if item.get("name") in RUNTIME_PROXY_EXCLUDED:
            continue
        if not destination_active(item, env):
            continue
        if user not in item.get("users", []):
            continue
        if _row_matches(host, item, env):
            return True
    return False
