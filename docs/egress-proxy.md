# Egress hostnames

Off-host names are checked by a local forward proxy. nftables decides which uid may open which path. Open WebUI and LiteLLM do not share a port with apt or MCP.

## Ports

`egress-proxy.service` listens on loopback only:

| Port | UID nftables allows onto that port | What the proxy allows |
|---|---|---|
| `127.0.0.1:8888` | `openwebui` | CONNECT to `login.microsoftonline.com` and `login.microsoft.com` |
| `127.0.0.1:8889` | `litellm` | CONNECT to `api.anthropic.com` only when `ANTHROPIC_BAA_ENABLED=true`; `AZURE_API_HOST` when that name is a single label ending in `.openai.azure.com` and one hyphen-separated token is a US region in `litellm/policy.yaml` |
| `127.0.0.1:8890` | `root` and `_apt` | Ubuntu archive and security hosts on 80 and 443, `dl.cloudsmith.io` on 443, and PyPI, GitHub, and Hugging Face only while `INSTALL_EGRESS=1` |
| `127.0.0.1:8891` | `policy-gateway` | CONNECT to `STACKJACK_MCP_HOST` and `COMPOSIO_MCP_HOST` when those names are set |

The Presidio analyzer has no off-host destination, so it has no proxy port and no `https_proxy`. `policy-gateway.service` sets `HTTPS_PROXY` to `127.0.0.1:8891` and `NO_PROXY` for loopback. systemd still denies every other address for that unit, so the process cannot dial an MCP host itself.

Ports 8888, 8889, 8890, and 8891 accept CONNECT to port 443. After that 200, the proxy reads one TLS record before it dials. The record must be a ClientHello. The proxy closes the tunnel without dialing when the SNI extension is missing, when a duplicate SNI extension is present, when more than one name is listed in that extension, when the `encrypted_client_hello` extension (type 65037) or the earlier `encrypted_server_name` type 65486 is present, or when the SNI host differs from the CONNECT host. The request line and that ClientHello share one deadline of about 10 seconds. A full proxy closes a new connection without a response once 64 connections are already in flight. A Host header on the CONNECT request, when the client sends one, must be that same CONNECT host. Port 80 has no TLS. On 8890 it is absolute-form `GET` or `HEAD` (`http://archive.ubuntu.com/...`). Exactly one Host header is required and it must match the URL host. Any Transfer-Encoding header, a duplicate Content-Length, a duplicate Host, or an obs-fold line is refused with 400. The request forwarded upstream sets `Connection: close`. `pkg.cloudflare.com` is not a destination.

The proxy resolves the name and dials the first address for which `ip.is_global` is true, after unwrapping an IPv4-mapped address. Multicast is refused. That drops loopback, link-local, RFC1918, CGNAT (`100.64.0.0/10`), IPv6 ULA, and documentation ranges. LiteLLM calls Azure OpenAI with an API key, so port 8889 does not allow `login.microsoftonline.com`. Open WebUI keeps that host for Entra sign-in. TCP/8088 on `127.0.0.1` and `127.0.0.2` rejects every uid except `openwebui` before the loopback accept.

## Other uids

The same nftables table also accepts:

- `egress-proxy`: TCP 80 and TCP 443, plus UDP/TCP 53, after the name check above
- `systemd-resolve`: UDP/TCP 53
- `systemd-timesync`: UDP 123. The client is `systemd-timesyncd` with `NTP=ntp.ubuntu.com` from `deploy/systemd/timesyncd.conf.d/local-ai.conf`. UDP has no SNI. This is not `time.cloudflare.com`.
- `root`: the `SIEM_PORT` when `SIEM_HOST` is set and the port is not 80 or 443
- DHCP renew and IPv6 neighbor discovery, with no uid match, so a dynamic address keeps working:
  - `udp sport 68 udp dport 67 accept` (DHCPv4)
  - `udp sport 546 udp dport 547 accept` (DHCPv6)
  - `icmpv6 type { nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept`

`root` and `_apt` have no blanket TCP 80 or TCP 443 accept. `policy-gateway` has no blanket TCP 443 accept. Apt on a later boot uses `/etc/apt/apt.conf.d/99local-ai-proxy`, which points at `127.0.0.1:8890`. `install.sh` writes that file after the proxy is up. The first apply still fetches packages before the filter is loaded.

## Verify on the VM

After `deploy/install.sh --apply`:

```bash
nft list table inet local_ai_egress
ss -ltnp | awk '/127.0.0.1:8888|127.0.0.1:8889|127.0.0.1:8890|127.0.0.1:8891/'
```

The table should show the `8888` reject for every uid except `openwebui`, the `8889` reject for every uid except `litellm`, the `8890` accepts for `root` and `_apt` followed by a reject, and the `8891` reject for every uid except `policy-gateway`. Those rules are before `oifname "lo" accept`. It should also show `udp sport 68 udp dport 67 accept`, `udp sport 546 udp dport 547 accept`, and `nd-neighbor-solicit`. It should not show a blanket `meta skuid root tcp dport { 80, 443 }` or `meta skuid policy-gateway tcp dport 443`.

```bash
sudo -u openwebui curl -sv --max-time 5 --proxy http://127.0.0.1:8888 https://api.anthropic.com/
sudo -u openwebui curl -sv --max-time 5 --proxy http://127.0.0.1:8889 https://api.anthropic.com/
sudo -u litellm curl -sv --max-time 5 --proxy http://127.0.0.1:8889 https://login.microsoftonline.com/
```

The first two fail (proxy 403, then an nftables reject because Open WebUI cannot open 8889). The third fails with proxy 403. A CONNECT from `openwebui` to `https://login.microsoftonline.com/` through port 8888 is the one that the proxy accepts.

### Reboot

`local-ai-egress-nft.service` is installed into `sysinit.target` and `multi-user.target`. The unit sets `Wants=network-pre.target` and `Before=network-pre.target`, so boot pulls the filter in and runs it before the network is configured. `local-ai-egress-refresh.timer` loads the table again about two minutes after boot and every five minutes. A static address is not required: the DHCP and neighbor-discovery accepts above are in that table.

```bash
systemctl is-enabled local-ai-egress-nft.service
systemctl is-enabled local-ai-egress-refresh.timer
```

Reboot, then as soon as SSH answers, without waiting two minutes:

```bash
nft list table inet local_ai_egress
```

The table is present, including `udp sport 68 udp dport 67 accept` and `nd-neighbor-solicit`.

### DHCP and neighbor discovery

```bash
nft list table inet local_ai_egress | grep -F 'udp sport 68 udp dport 67 accept'
nft list table inet local_ai_egress | grep -F 'udp sport 546 udp dport 547 accept'
nft list table inet local_ai_egress | grep -F 'nd-neighbor-solicit'
```

Each command prints one rule. UFW's IPv4 owner block also accepts UDP sport 68 to dport 67. The IPv6 lines are spliced into `before6.rules` from `deploy/ufw/owner6.rules`.

### Non-owner uid

`nobody` is not an owner of any accept. Both commands must fail. The first is dropped by the chain policy. The second is rejected because 8890 allows only `root` and `_apt`, and that reject is before the loopback accept.

```bash
sudo -u nobody curl -sv --max-time 5 https://archive.ubuntu.com/ || echo "non-owner dropped"
sudo -u nobody curl -sv --max-time 5 --proxy http://127.0.0.1:8890 https://archive.ubuntu.com/ || echo "non-owner dropped"
```

### Root on the other proxy ports

`root` may open 8890. nftables rejects that uid on 8888, 8889, and 8891, and those rules are before the loopback accept. Each command fails. The proxy does not answer them.

```bash
sudo -u root curl -sv --max-time 5 --proxy http://127.0.0.1:8888 https://login.microsoftonline.com/ || echo "root blocked"
sudo -u root curl -sv --max-time 5 --proxy http://127.0.0.1:8889 https://login.microsoftonline.com/ || echo "root blocked"
sudo -u root curl -sv --max-time 5 --proxy http://127.0.0.1:8891 https://login.microsoftonline.com/ || echo "root blocked"
```

### Host mismatch on 8890

`root` can open 8890. This request uses the archive URL and a different Host header. The proxy returns 403.

```bash
sudo -u root curl -sv --max-time 5 --proxy http://127.0.0.1:8890 --header 'Host: evil.example' http://archive.ubuntu.com/ubuntu/ || echo "host mismatch"
```

`python3 scripts/egress_nft.py` prints the rules the apply step loads. Compare that text with `nft list table inet local_ai_egress`.
