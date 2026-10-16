# Host hardening (Ubuntu Server LTS)

`deploy/install.sh --apply` is the idempotent path. `deploy/install.sh --check` only validates the repo (this is what CI runs).

## LUKS

Full-disk encryption at install, or a LUKS volume mounted on `/var/lib/local-ai-stack` before the units start. `deploy/install.sh --apply` runs `scripts/check_luks.py --target /var/lib/local-ai-stack` and stops if that path is not on a LUKS mapping. `--check` only runs the walker’s self-check, so CI does not need an encrypted disk. `install.sh` bind-mounts that tree over `/var/lib/postgresql` so the database is on the same volume. Escrow the passphrase separately from the backup repo. Details: `docs/encrypted-volumes.md`.

## UFW

Default deny incoming and default deny outgoing. Inbound exceptions are SSH and 443 from `VPN_SSH_CIDR`, plus loopback. Outbound allows are owner-matched UFW rules. Ubuntu’s UFW applies those through nftables. systemd `IPAddressAllow` does not accept hostnames, so it is not used for Entra, Anthropic, or Azure. The Open WebUI REJECT for LiteLLM is spliced ahead of the stock `-o lo -j ACCEPT` in `before.rules`, because that accept would otherwise pass the loopback packet first. `api.anthropic.com` is added for the `litellm` user only when `ANTHROPIC_BAA_ENABLED=true`. PyPI, the spaCy wheel host, and Hugging Face are install-time allows and are removed on the final `host/ufw.sh` run. `local-ai-egress-refresh.timer` re-resolves the allowlist every five minutes. The hostname forward proxy that replaces this address list is described in `docs/egress-proxy.md` and is still a deploy blocker. Optional Azure, DNS, and SIEM hosts are added only when those variables are set. Cloudflare tunnel destinations are not installed while `cloudflared_enabled` is false.

There is no container runtime and no published Docker port. Caddy binds `${VPN_BIND_IP:-127.0.0.1}:443` and needs `CAP_NET_BIND_SERVICE` to do that. Every other unit has an empty `CapabilityBoundingSet=`. The policy gateway allows only `127.0.0.1` and `127.0.0.2`. Open WebUI denies `127.0.0.2`, which is where LiteLLM listens. If a Docker daemon is already on the host and its `daemon.json` contains `tcp://`, apply refuses to continue.

## unattended-upgrades

Security updates install daily. Automatic reboot is 03:30. Python lock bumps are monthly and wait for a review of the release notes. The hashes in `requirements/*.txt` do not float. The spaCy model pin is `en_core_web_lg==3.8.0`.

## CIS-style baseline

- SSH keys only, no root login: `host/ssh/00-local-ai-vpn.conf` (first match wins over `deploy/ssh/99-local-ai.conf`). Reloading sshd is gated by `APPLY_SSH_HARDENING=1` so an apply does not lock the operator out by surprise.
- `qemu-guest-agent` is installed with `guest-exec` and `guest-file` RPCs blocked. Proxmox backups can still freeze the filesystem.
- `auditd`, AppArmor, and a small sysctl drop-in are installed by the script.
- Package set is the list in `deploy/services.yaml` (Python, Postgres, Caddy, cloudflared, WireGuard, UFW, unattended-upgrades, restic, openssl). No container engine.
- `systemd-timesyncd` for time sync. NTP target in the egress list: `time.cloudflare.com`, uid `systemd-timesync`.
- WireGuard is installed and left stopped until `/etc/wireguard/wg0.conf` exists (mode 0600, not in git). The example in `deploy/wireguard/` has no private key.
- Journald `SystemMaxFileSize=10M` and `SystemMaxFiles=5`. LiteLLM is `LITELLM_LOG=ERROR`. Open WebUI `GLOBAL_LOG_LEVEL=WARNING` and audit level is `METADATA` so chat bodies are not written to stdout.
- Unattended-upgrades come from `host/apt/52local-ai-unattended`: security origins only, reboot at 03:30.

## Log retention

Journald rotates locally (operational). The Postgres `audit_event` table and any SIEM copy are the compliance record: 6 years for HIPAA documentation, 5 years for NYDFS 500.6. Chat history is not an audit log; it is purged at 30 days.

Who reviews: the designated security reviewer. Fail-closed and blocked-tool rows within one business day. A weekly sample of allow rows. Quarterly access review of Entra assignments and virtual keys.

## Backups

restic or borg, encrypted, 3-2-1, one copy immutable/offsite. Keys held separately from the repo. Quarterly restore test. RTO/RPO 24h/24h. While the stack is down, work stays in the green lane. Do not fall back to an unredacted tool.

## Egress list

See `deploy/egress-destinations.yaml`. Default is deny. Steady-state hosts are Entra login (user `openwebui`), Ubuntu archives, the Caddy and cloudflared apt hosts (user `root`), and NTP. `api.anthropic.com` is present for `litellm` only when `ANTHROPIC_BAA_ENABLED=true`. PyPI, GitHub, and Hugging Face are present only while `INSTALL_EGRESS=1`, which the final firewall apply clears. The Azure OpenAI host is added only when `AZURE_API_HOST` is set to that resource’s `*.openai.azure.com` name, and only for `litellm`. StackJack and Composio hosts are optional and unset. Cloudflared’s `argotunnel` hosts are not allowed, and the cloudflared unit is disabled.
