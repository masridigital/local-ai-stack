"""nftables output filter.

Off-host TCP is limited to the egress-proxy user. That process is the only
one that dials an allowlisted FQDN. Loopback stays open after the LiteLLM
port reject, so Open WebUI still cannot reach 127.0.0.2:4000.
"""

from __future__ import annotations

LITELLM_ADDRS = ("127.0.0.2", "127.0.0.1")
PROXY_USER = "egress-proxy"


def render_nft() -> str:
    rejects = "\n".join(f"    ip daddr {addr} tcp dport 4000 reject" for addr in LITELLM_ADDRS)
    return (
        "destroy table inet local_ai_egress\n"
        "table inet local_ai_egress {\n"
        "  chain output {\n"
        "    type filter hook output priority filter; policy drop;\n"
        "    ct state established,related accept\n"
        f"{rejects}\n"
        '    oifname "lo" accept\n'
        f"    meta skuid {PROXY_USER} tcp dport {{ 80, 443 }} accept\n"
        "  }\n"
        "}\n"
    )


if __name__ == "__main__":
    print(render_nft(), end="")
