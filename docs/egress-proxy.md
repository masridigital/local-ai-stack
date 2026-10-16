# Egress hostnames

systemd `IPAddressAllow` ignores hostnames, and a one-time DNS lookup goes stale when a CDN rotates the address. Two controls cover that.

## What this tree does now

`local-ai-egress-refresh.timer` runs `deploy/egress-refresh.sh` two minutes after boot and every five minutes after that. The script clears `INSTALL_EGRESS`, resolves the active destinations, splices the owner rules in front of UFW’s loopback OUTPUT accept, and reloads UFW. `ANTHROPIC_BAA_ENABLED` and `AZURE_API_HOST` come from `/etc/local-ai-stack/egress.env`, which `install.sh` rewrites on each apply. The Anthropic destination stays absent unless that switch is `true`.

That timer is the interim control. It is not a hostname allowlist. A lookup that changes between runs is allowed until the next run, and a name that briefly resolves to an unexpected address is allowed for that interval.

## Follow-up, still a deploy blocker

Before PHI, replace the resolved address list with a local forward proxy that allows destinations by name:

- The proxy listens on a loopback port. Its configuration is the FQDN allowlist in `deploy/egress-destinations.yaml`, including the same BAA and install-time gates.
- LiteLLM, Open WebUI, and root apt use that proxy (`HTTP_PROXY` / `HTTPS_PROXY`). Their units accept only the proxy address.
- The proxy user is the only uid that may open off-host connections, and it checks the TLS SNI or HTTP host against the allowlist before connecting.
- UFW then default-denies the service users without embedding CDN addresses.

Until that proxy is in place, do not treat the stack as ready for PHI. The refresh timer is what keeps the current rules from freezing an old address.
