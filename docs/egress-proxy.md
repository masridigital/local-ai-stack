# Egress hostnames

Off-host TCP from this host goes through a local forward proxy. The proxy allows destinations by FQDN. nftables allows only the `egress-proxy` user to open TCP/80 and TCP/443. Service users talk to `127.0.0.1:8888` and are rejected if they dial anywhere else.

## Proxy

`egress-proxy.service` runs `deploy/egress-proxy.py` as `egress-proxy` on `127.0.0.1:8888`. It loads `deploy/egress-destinations.yaml` and `/etc/local-ai-stack/egress.env`.

Allowed names:

- Entra: `login.microsoftonline.com` and `login.microsoft.com` on port 443.
- Anthropic: `api.anthropic.com` only when `ANTHROPIC_BAA_ENABLED=true`.
- The Azure OpenAI host on the Presidio-gated path: `AZURE_API_HOST` when it is set, and only if the name ends in `.openai.azure.com`.

IP literals are refused. A name that is not on the list is refused before the proxy dials it.

LiteLLM, Open WebUI, and the Presidio analyzer set `https_proxy` to that listener. `NO_PROXY` keeps loopback traffic (Presidio, the gateway, Postgres, LiteLLM) off the proxy.

## Firewall

`scripts/egress_nft.py` renders table `inet local_ai_egress`:

- established traffic is accepted
- TCP/4000 to `127.0.0.2` and `127.0.0.1` is rejected before the loopback accept
- other loopback traffic is accepted
- TCP/80 and TCP/443 are accepted only for uid `egress-proxy`

UFW stays default deny. Owner rules reject `litellm`, `openwebui`, and the other service users. They accept off-host TCP only for `egress-proxy`. `local-ai-egress-refresh.timer` reloads that table and restarts the proxy. It does not pin CDN addresses.

NTP is not an HTTP CONNECT flow. It is not opened by this table.
