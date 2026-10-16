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

# These users never dial off-host. Their HTTPS clients use the local proxy.
DIRECT_DENY_USERS = (
    "presidio-analyzer",
    "presidio-anonymizer",
    "policy-gateway",
    "postgres",
    "caddy",
    "litellm",
    "openwebui",
)
PROXY_USER = "egress-proxy"

# Open WebUI must not open a socket to LiteLLM. This runs before the loopback accept.
LITELLM_DENY = (
    "-A ufw-before-output -m owner --uid-owner openwebui -d 127.0.0.2 -p tcp --dport 4000 -j REJECT",
    "-A ufw-before-output -m owner --uid-owner openwebui -d 127.0.0.1 -p tcp --dport 4000 -j REJECT",
)
# Only the openwebui uid may open the policy gateway. This is spliced ahead of
# the loopback accept, which would otherwise allow every local uid.
GATEWAY_UID_GATE = (
    "-A ufw-before-output -m owner ! --uid-owner openwebui -d 127.0.0.1 -p tcp --dport 8088 -j REJECT",
    "-A ufw-before-output -m owner ! --uid-owner openwebui -d 127.0.0.2 -p tcp --dport 8088 -j REJECT",
)


def load_destinations(path: Path) -> dict:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if raw.get("default") != "deny":
        raise ValueError("egress default must be deny")
    return raw


def destination_active(item: dict, env: dict[str, str]) -> bool:
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


def active_destinations(raw: dict, env: dict[str, str] | None = None) -> list[dict]:
    env = env or {}
    active = []
    for item in raw["destinations"]:
        if not destination_active(item, env):
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
    if configured and not item.get("env_value"):
        suffix = item.get("host_suffix")
        if suffix and not configured.lower().rstrip(".").endswith(suffix.lower()):
            raise ValueError(f"{configured} does not match {suffix}")
        hosts.append(configured)
    return hosts


def render_user_rules(raw: dict, env: dict[str, str] | None = None) -> str:
    lines = [
        "# FQDN allowlist for the local egress proxy. These are not global firewall allows.",
        "# Optional hosts are added only when their env var is set. cloudflared is not installed.",
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
    lines = [
        "# Owner-matched OUTPUT rules. Proxy ports are uid-locked before loopback accept.",
        "# Apt and MCP names are checked on their own proxy ports. DNS, NTP, and optional SIEM stay uid accepts.",
        "# DHCPv4 renew is sport 68 to dport 67. IPv6 ND and DHCPv6 are in owner6.rules.",
        "# Hostnames are comments here. They are not firewall matches.",
    ]
    for item in active:
        users = ",".join(item["users"])
        for host in _hosts(item, env):
            for port in _ports(item, env):
                lines.append(f"# proxy for {users} -> {host}:{port}/{item['proto']}")
    lines.extend(LITELLM_DENY)
    lines.append(
        "-A ufw-before-output -d 127.0.0.1 -p tcp --dport 8888 -m owner ! --uid-owner openwebui -j REJECT"
    )
    lines.append(
        "-A ufw-before-output -d 127.0.0.1 -p tcp --dport 8889 -m owner ! --uid-owner litellm -j REJECT"
    )
    lines.append("-A ufw-before-output -d 127.0.0.1 -p tcp --dport 8890 -m owner --uid-owner root -j ACCEPT")
    lines.append("-A ufw-before-output -d 127.0.0.1 -p tcp --dport 8890 -m owner --uid-owner _apt -j ACCEPT")
    lines.append("-A ufw-before-output -d 127.0.0.1 -p tcp --dport 8890 -j REJECT")
    lines.append(
        "-A ufw-before-output -d 127.0.0.1 -p tcp --dport 8891 -m owner ! --uid-owner policy-gateway -j REJECT"
    )
    lines.extend(GATEWAY_UID_GATE)
    lines.append("-A ufw-before-output -o lo -j ACCEPT")
    lines.append(f"-A ufw-before-output -m owner --uid-owner {PROXY_USER} -p tcp --dport 80 -j ACCEPT")
    lines.append(f"-A ufw-before-output -m owner --uid-owner {PROXY_USER} -p tcp --dport 443 -j ACCEPT")
    lines.append(f"-A ufw-before-output -m owner --uid-owner {PROXY_USER} -p udp --dport 53 -j ACCEPT")
    lines.append(f"-A ufw-before-output -m owner --uid-owner {PROXY_USER} -p tcp --dport 53 -j ACCEPT")
    lines.append("-A ufw-before-output -m owner --uid-owner systemd-resolve -p udp --dport 53 -j ACCEPT")
    lines.append("-A ufw-before-output -m owner --uid-owner systemd-resolve -p tcp --dport 53 -j ACCEPT")
    lines.append("-A ufw-before-output -m owner --uid-owner systemd-timesync -p udp --dport 123 -j ACCEPT")
    lines.append("-A ufw-before-output -p udp --sport 68 --dport 67 -j ACCEPT")
    siem_port = env.get("SIEM_PORT", "").strip()
    if env.get("SIEM_HOST", "").strip() and siem_port.isdigit() and siem_port not in {"80", "443"}:
        lines.append(f"-A ufw-before-output -m owner --uid-owner root -p tcp --dport {int(siem_port)} -j ACCEPT")
    for user in DIRECT_DENY_USERS:
        lines.append(f"-A ufw-before-output -m owner --uid-owner {user} -j REJECT")
    if resolutions:
        # Resolved addresses are not installed. The proxy dials the name itself.
        lines.append("# resolved addresses are ignored")
    return "\n".join(lines) + "\n"


def render_nd_rules() -> str:
    """IPv6 rules spliced into before6.rules. Names are the iptables icmpv6 types."""
    lines = [
        "# DHCPv6 renew and IPv6 neighbor discovery. Spliced into before6.rules.",
        "-A ufw6-before-output -p udp --sport 546 --dport 547 -j ACCEPT",
        "-A ufw6-before-output -p ipv6-icmp --icmpv6-type router-solicitation -j ACCEPT",
        "-A ufw6-before-output -p ipv6-icmp --icmpv6-type router-advertisement -j ACCEPT",
        "-A ufw6-before-output -p ipv6-icmp --icmpv6-type neighbour-solicitation -j ACCEPT",
        "-A ufw6-before-output -p ipv6-icmp --icmpv6-type neighbour-advertisement -j ACCEPT",
    ]
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


def splice_before_rules(
    before_text: str,
    block: str,
    marker: str = "-A ufw-before-output -o lo -j ACCEPT",
    begin: str = "# BEGIN local-ai-owner",
    end: str = "# END local-ai-owner",
) -> str:
    """Insert owner rules before UFW's loopback OUTPUT accept.

    Ubuntu's before.rules accepts every loopback packet before the established
    rule. A REJECT spliced after that accept never sees 127.0.0.1 or 127.0.0.2.
    """
    if begin in before_text and end in before_text:
        start = before_text.index(begin)
        finish = before_text.index(end) + len(end)
        if before_text[finish:].startswith("\n"):
            finish += 1
        before_text = before_text[:start] + before_text[finish:]
    payload = f"{begin}\n{block.rstrip()}\n{end}\n"
    if marker not in before_text:
        raise ValueError("ufw before.rules has no loopback OUTPUT accept to anchor on")
    insert_at = before_text.index(marker)
    return before_text[:insert_at] + payload + before_text[insert_at:]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dest", type=Path, required=True)
    parser.add_argument("--user-rules", type=Path)
    parser.add_argument("--owner-rules", type=Path)
    parser.add_argument("--nd-rules", type=Path)
    parser.add_argument("--apply-ufw", action="store_true")
    args = parser.parse_args()
    raw = load_destinations(args.dest)
    env = dict(**{key: value for key, value in __import__("os").environ.items()})
    if args.user_rules:
        args.user_rules.write_text(render_user_rules(raw), encoding="utf-8")
    if args.owner_rules:
        args.owner_rules.write_text(render_owner_rules(raw, {}), encoding="utf-8")
    if args.nd_rules:
        args.nd_rules.write_text(render_nd_rules(), encoding="utf-8")
    if args.apply_ufw:
        block = render_owner_rules(raw, {}, env)
        before = Path("/etc/ufw/before.rules")
        before.write_text(splice_before_rules(before.read_text(encoding="utf-8"), block), encoding="utf-8")
        before6 = Path("/etc/ufw/before6.rules")
        if before6.is_file():
            nd = splice_before_rules(
                before6.read_text(encoding="utf-8"),
                render_nd_rules(),
                marker="-A ufw6-before-output -o lo -j ACCEPT",
                begin="# BEGIN local-ai-nd",
                end="# END local-ai-nd",
            )
            before6.write_text(nd, encoding="utf-8")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001
        print(exc, file=sys.stderr)
        raise SystemExit(1) from exc
