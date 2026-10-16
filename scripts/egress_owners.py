"""Render the default-deny egress list as owner-matched firewall rules.

Global `ufw allow out` rules are not used. install.sh resolves each host and
inserts ACCEPT lines that match both the destination and the service uid.
"""

from __future__ import annotations

import argparse
import socket
import sys
from pathlib import Path

import yaml

NO_EGRESS_CANDIDATES = (
    "presidio-analyzer",
    "presidio-anonymizer",
    "policy-gateway",
    "postgres",
    "caddy",
    "cloudflared",
)


def load_destinations(path: Path) -> dict:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if raw.get("default") != "deny":
        raise ValueError("egress default must be deny")
    return raw


def active_destinations(raw: dict, env: dict[str, str] | None = None) -> list[dict]:
    env = env or {}
    active = []
    for item in raw["destinations"]:
        if item.get("enabled", True) is False:
            continue
        if item.get("optional") and item.get("env") and not env.get(item["env"], ""):
            continue
        if not item.get("users"):
            raise ValueError(f"destination {item.get('name')} has no users")
        active.append(item)
    return active


def _ports(item: dict, env: dict[str, str]) -> list[int]:
    if item.get("port_env"):
        configured = env.get(item["port_env"], "")
        if not configured:
            raise ValueError(f"destination {item.get('name')} is missing {item['port_env']}")
        return [int(configured)]
    if "ports" in item:
        return [int(port) for port in item["ports"]]
    return [int(item["port"])]


def _hosts(item: dict, env: dict[str, str]) -> list[str]:
    hosts = list(item.get("hosts") or [])
    env_name = item.get("env")
    configured = env.get(env_name, "") if env_name else ""
    if configured:
        suffix = item.get("host_suffix")
        if suffix and not configured.lower().rstrip(".").endswith(suffix.lower()):
            raise ValueError(f"{configured} does not match {suffix}")
        hosts.append(configured)
    return hosts


def render_user_rules(raw: dict, env: dict[str, str] | None = None) -> str:
    lines = [
        "# Host allowlist. install.sh installs these as owner-matched OUTPUT rules, not global allows.",
        "# Optional hosts are added only when their env var is set. cloudflared stays off.",
        "default deny incoming",
        "default deny outgoing",
    ]
    for item in active_destinations(raw, env):
        users = ",".join(item["users"])
        lines.append(f"# user {users}")
        for host in _hosts(item, env or {}):
            for port in _ports(item, env or {}):
                lines.append(f"allow out to {host} port {port} proto {item['proto']}")
    return "\n".join(lines) + "\n"


def render_owner_rules(raw: dict, resolutions: dict[str, list[str]], env: dict[str, str] | None = None) -> str:
    env = env or {}
    active = active_destinations(raw, env)
    egress_users = {user for item in active for user in item["users"]}
    lines = [
        "# Owner-matched OUTPUT rules. Loopback first, then per-uid ACCEPTs, then REJECT for users with no egress.",
        "# ACCEPT lines for resolved addresses are inserted by install.sh. This file is the committed policy.",
    ]
    for item in active:
        users = ",".join(item["users"])
        for host in _hosts(item, env):
            for port in _ports(item, env):
                lines.append(f"# {users} -> {host}:{port}/{item['proto']}")
    lines.append("-A ufw-before-output -o lo -j ACCEPT")
    for item in active:
        for host in _hosts(item, env):
            for ip in resolutions.get(host, []):
                for user in item["users"]:
                    for port in _ports(item, env):
                        lines.append(
                            f"-A ufw-before-output -m owner --uid-owner {user} -d {ip} -p {item['proto']} --dport {port} -j ACCEPT"
                        )
    for user in NO_EGRESS_CANDIDATES:
        if user in egress_users:
            continue
        lines.append(f"-A ufw-before-output -m owner --uid-owner {user} -j REJECT")
    return "\n".join(lines) + "\n"


def resolve_hosts(raw: dict, env: dict[str, str] | None = None) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for item in active_destinations(raw, env):
        for host in _hosts(item, env or {}):
            if host in found:
                continue
            infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
            ips = sorted({info[4][0] for info in infos})
            if not ips:
                raise OSError(f"no address for {host}")
            found[host] = ips
    return found


def splice_before_rules(before_text: str, block: str) -> str:
    begin = "# BEGIN local-ai-owner"
    end = "# END local-ai-owner"
    payload = f"{begin}\n{block.rstrip()}\n{end}\n"
    if begin in before_text and end in before_text:
        start = before_text.index(begin)
        finish = before_text.index(end) + len(end)
        # keep a trailing newline if the original had one after the marker
        suffix = before_text[finish:]
        if suffix.startswith("\n"):
            suffix = suffix[1:]
        return before_text[:start] + payload + suffix
    marker = "-A ufw-before-output -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
    if marker not in before_text:
        raise ValueError("ufw before.rules has no established OUTPUT rule to anchor on")
    insert_at = before_text.index(marker) + len(marker)
    return before_text[:insert_at] + "\n" + payload + before_text[insert_at:]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dest", type=Path, required=True)
    parser.add_argument("--user-rules", type=Path)
    parser.add_argument("--owner-rules", type=Path)
    parser.add_argument("--apply-ufw", action="store_true")
    args = parser.parse_args()
    raw = load_destinations(args.dest)
    env = dict(**{key: value for key, value in __import__("os").environ.items()})
    if args.user_rules:
        args.user_rules.write_text(render_user_rules(raw), encoding="utf-8")
    if args.owner_rules:
        args.owner_rules.write_text(render_owner_rules(raw, {}), encoding="utf-8")
    if args.apply_ufw:
        resolutions = resolve_hosts(raw, env)
        block = render_owner_rules(raw, resolutions, env)
        before = Path("/etc/ufw/before.rules")
        before.write_text(splice_before_rules(before.read_text(encoding="utf-8"), block), encoding="utf-8")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001
        print(exc, file=sys.stderr)
        raise SystemExit(1) from exc
