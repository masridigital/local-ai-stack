"""nftables output filter.

Each runtime proxy port accepts only that service uid, and only before the
loopback accept. Off-host TCP/443 for allowlisted names is the egress-proxy
user. DNS, NTP, apt, SIEM, and MCP are separate skuid accepts.
"""

from __future__ import annotations

import os

LITELLM_ADDRS = ("127.0.0.2", "127.0.0.1")
PROXY_USER = "egress-proxy"
# service user, loopback port
PROXY_PORTS = (
    ("openwebui", 8888),
    ("litellm", 8889),
)


def render_nft(env: dict[str, str] | None = None) -> str:
    env = env or {}
    rejects = "\n".join(f"    ip daddr {addr} tcp dport 4000 reject" for addr in LITELLM_ADDRS)
    port_rejects = "\n".join(
        f"    ip daddr 127.0.0.1 tcp dport {port} meta skuid != {user} reject" for user, port in PROXY_PORTS
    )
    lines = [
        "destroy table inet local_ai_egress",
        "table inet local_ai_egress {",
        "  chain output {",
        "    type filter hook output priority filter; policy drop;",
        "    ct state established,related accept",
        rejects,
        port_rejects,
        '    oifname "lo" accept',
        f"    meta skuid {PROXY_USER} tcp dport 443 accept",
        f"    meta skuid {PROXY_USER} meta l4proto {{ tcp, udp }} th dport 53 accept",
        "    meta skuid systemd-resolve meta l4proto { tcp, udp } th dport 53 accept",
        "    meta skuid systemd-timesync udp dport 123 accept",
        "    meta skuid _apt tcp dport { 80, 443 } accept",
        "    meta skuid root tcp dport { 80, 443 } accept",
    ]
    siem_port = env.get("SIEM_PORT", "").strip()
    if env.get("SIEM_HOST", "").strip() and siem_port.isdigit() and siem_port not in {"80", "443"}:
        lines.append(f"    meta skuid root tcp dport {int(siem_port)} accept")
    if env.get("STACKJACK_MCP_HOST", "").strip() or env.get("COMPOSIO_MCP_HOST", "").strip():
        lines.append("    meta skuid policy-gateway tcp dport 443 accept")
    lines.extend(["  }", "}", ""])
    return "\n".join(lines)


if __name__ == "__main__":
    print(render_nft(dict(os.environ)), end="")
