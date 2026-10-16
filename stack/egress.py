"""Default-deny egress list. Destinations are explicit; nothing else is allowed."""

from __future__ import annotations

from pathlib import Path

import yaml


def load_destinations(path: Path) -> dict:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if raw.get("default") != "deny":
        raise ValueError("egress default must be deny")
    return raw


def allowed_hosts(raw: dict, env: dict[str, str]) -> list[str]:
    hosts: list[str] = []
    for item in raw["destinations"]:
        if item.get("enabled", True) is False:
            continue
        if item.get("optional") and not env.get(item.get("env", ""), ""):
            # Optional rows with static hosts stay disabled unless enabled: true.
            if "hosts" in item and item.get("optional"):
                continue
        hosts.extend(item.get("hosts") or [])
        env_name = item.get("env")
        if env_name and env.get(env_name):
            hosts.append(env[env_name])
    return hosts


def host_allowed(host: str, raw: dict, env: dict[str, str]) -> bool:
    host = host.lower().rstrip(".")
    for item in raw["destinations"]:
        if item.get("enabled", True) is False:
            continue
        for listed in item.get("hosts") or []:
            if host == listed.lower():
                return True
        env_name = item.get("env")
        configured = env.get(env_name, "").lower() if env_name else ""
        if configured and host == configured:
            suffix = item.get("host_suffix")
            if suffix and not host.endswith(suffix.lower()):
                return False
            return True
    return False
