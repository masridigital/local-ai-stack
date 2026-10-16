"""nftables output filter for the LiteLLM listener.

systemd IPAddressAllow ignores hostnames, and UFW's stock loopback accept
runs before a later REJECT. This table rejects TCP/4000 on the LiteLLM
loopback addresses before it accepts other loopback traffic. `nft -c`
checks the syntax without installing the table.
"""

from __future__ import annotations

LITELLM_ADDRS = ("127.0.0.2", "127.0.0.1")


def render_nft() -> str:
    rejects = "\n".join(
        f"    ip daddr {addr} tcp dport 4000 reject" for addr in LITELLM_ADDRS
    )
    return (
        "table inet local_ai_egress {\n"
        "  chain output {\n"
        "    type filter hook output priority filter; policy drop;\n"
        "    ct state established,related accept\n"
        f"{rejects}\n"
        '    oifname "lo" accept\n'
        "  }\n"
        "}\n"
    )
