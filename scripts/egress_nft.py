"""nftables output filter.

Runtime proxy ports accept only that service uid, and only before the loopback
accept. Apt (root and _apt) and the policy gateway use their own loopback
ports. The proxy user dials 80 and 443 after the name check. DNS, NTP, and an
optional SIEM port stay skuid accepts. DHCP renew and IPv6 neighbor discovery
are allowed so the host does not need a static address.
"""

from __future__ import annotations

import os

LITELLM_ADDRS = ("127.0.0.2", "127.0.0.1")
PROXY_USER = "egress-proxy"
# service user, loopback port. 8890 and 8891 are rendered separately.
PROXY_PORTS = (
    ("openwebui", 8888),
    ("litellm", 8889),
)


def render_nft(env: dict[str, str] | None = None) -> str:
    env = env or {}
    lines = [
        "destroy table inet local_ai_egress",
        "table inet local_ai_egress {",
        "  chain output {",
        "    type filter hook output priority filter; policy drop;",
        "    ct state established,related accept",
        "    udp sport 68 udp dport 67 accept",
        "    udp sport 546 udp dport 547 accept",
        "    icmpv6 type { nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept",
    ]
    lines.extend(f"    ip daddr {addr} tcp dport 4000 reject" for addr in LITELLM_ADDRS)
    lines.extend(
        f"    ip daddr 127.0.0.1 tcp dport {port} meta skuid != {user} reject" for user, port in PROXY_PORTS
    )
    lines.extend(
        [
            "    ip daddr 127.0.0.1 tcp dport 8890 meta skuid root accept",
            "    ip daddr 127.0.0.1 tcp dport 8890 meta skuid _apt accept",
            "    ip daddr 127.0.0.1 tcp dport 8890 reject",
            "    ip daddr 127.0.0.1 tcp dport 8891 meta skuid != policy-gateway reject",
            '    oifname "lo" accept',
            f"    meta skuid {PROXY_USER} tcp dport {{ 80, 443 }} accept",
            f"    meta skuid {PROXY_USER} meta l4proto {{ tcp, udp }} th dport 53 accept",
            "    meta skuid systemd-resolve meta l4proto { tcp, udp } th dport 53 accept",
            "    meta skuid systemd-timesync udp dport 123 accept",
        ]
    )
    siem_port = env.get("SIEM_PORT", "").strip()
    if env.get("SIEM_HOST", "").strip() and siem_port.isdigit() and siem_port not in {"80", "443"}:
        lines.append(f"    meta skuid root tcp dport {int(siem_port)} accept")
    lines.extend(["  }", "}", ""])
    return "\n".join(lines)


if __name__ == "__main__":
    print(render_nft(dict(os.environ)), end="")
