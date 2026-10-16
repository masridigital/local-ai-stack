# Egress hostnames

Off-host names are checked by a local forward proxy. nftables decides which uid may open which path. The proxy does not carry apt, Cloudsmith, `pkg.cloudflare.com`, SIEM, StackJack, or Composio.

## Ports

`egress-proxy.service` listens on loopback only:

| Port | UID nftables allows onto that port | Names the proxy will CONNECT |
|---|---|---|
| `127.0.0.1:8888` | `openwebui` | `login.microsoftonline.com`, `login.microsoft.com` |
| `127.0.0.1:8889` | `litellm` | `api.anthropic.com` only when `ANTHROPIC_BAA_ENABLED=true`; `AZURE_API_HOST` when that name is a single label ending in `.openai.azure.com` and one hyphen-separated token is a US region in `litellm/policy.yaml` |

The Presidio analyzer has no off-host destination, so it has no proxy port and no `https_proxy`.

CONNECT to port 443 is the only accepted method. The proxy resolves the name and dials the first address that is not loopback, link-local, RFC1918, CGNAT (`100.64.0.0/10`), or IPv6 ULA. Any other answer is refused.

## Other uids

The same nftables table also accepts:

- `systemd-resolve` and `egress-proxy`: UDP/TCP 53
- `systemd-timesync`: UDP 123
- `_apt` and `root`: TCP 80 and TCP 443, for apt and unattended-upgrades
- `root`: the `SIEM_PORT` when `SIEM_HOST` is set and the port is not 80 or 443
- `policy-gateway`: TCP 443 only when `STACKJACK_MCP_HOST` or `COMPOSIO_MCP_HOST` is set

Those rows are not in the proxy allowlist.

## Verify on the VM

After `deploy/install.sh --apply`:

```bash
nft list table inet local_ai_egress
ss -ltnp | awk '/127.0.0.1:8888|127.0.0.1:8889/'
```

The table should show the `8888` reject for every uid except `openwebui`, the `8889` reject for every uid except `litellm`, both of those before `oifname "lo" accept`, and the skuid accepts above.

```bash
sudo -u openwebui curl -sv --max-time 5 --proxy http://127.0.0.1:8888 https://api.anthropic.com/
sudo -u openwebui curl -sv --max-time 5 --proxy http://127.0.0.1:8889 https://api.anthropic.com/
sudo -u litellm curl -sv --max-time 5 --proxy http://127.0.0.1:8889 https://login.microsoftonline.com/
```

The first two fail (proxy 403, then an nftables reject because Open WebUI cannot open 8889). The third fails with proxy 403. A CONNECT from `openwebui` to `https://login.microsoftonline.com/` through port 8888 is the one that the proxy accepts.

`python3 scripts/egress_nft.py` prints the rules the apply step loads. Compare that text with `nft list table inet local_ai_egress`.
