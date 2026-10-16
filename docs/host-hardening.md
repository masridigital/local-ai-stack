# Host hardening (Ubuntu Server LTS)

`deploy/install.sh --apply` is the idempotent path. `deploy/install.sh --check` only validates the repo (this is what CI runs).

## LUKS

Full-disk encryption at install, or a LUKS volume mounted on `/var/lib/local-ai-stack` and `/var/lib/docker` before the compose unit starts. Escrow the passphrase separately from the backup repo. Details: `docs/encrypted-volumes.md`.

## UFW

Default deny incoming and default deny outgoing. The only inbound exception is SSH from `VPN_SSH_CIDR`. Outbound allows are the hosts in `deploy/ufw/user.rules`, plus optional Azure, DNS, and SIEM hosts when those variables are set at apply time. Cloudflare tunnel destinations are not installed while `cloudflared_enabled` is false.

Docker published ports bypass the UFW input chain. This stack publishes only Caddy, on `${LAN_BIND_IP:-127.0.0.1}:443`. Postgres, Presidio, LiteLLM, and the policy gateway have no host ports. `daemon.json` has no `tcp://` listener.

## unattended-upgrades

Security updates install daily. Automatic reboot is 03:30. Container image bumps are monthly and wait for Marko to read the release notes. Digests in `images.lock.yaml` do not float.

## CIS-style baseline

- SSH keys only, no root login: `deploy/ssh/99-local-ai.conf`. Reloading sshd is gated by `APPLY_SSH_HARDENING=1` so an apply does not lock the operator out by surprise.
- `auditd`, AppArmor, and a small sysctl drop-in are installed by the script.
- Package set is the list in `install.sh` (Docker, UFW, unattended-upgrades, restic, openssl). No extra services.
- `systemd-timesyncd` for time sync. NTP target in the egress list: `time.cloudflare.com`.
- Docker: live-restore, json-file log limits (10m x 5), no TCP socket, userland proxy off. Rootless and userns-remap are not turned on in this unit because they break the pinned official images’ volume permissions; revisit with Marko before PHI if the host is shared.
- Log drivers must not be DEBUG. LiteLLM is `LITELLM_LOG=ERROR`. Open WebUI audit level is `METADATA` so chat bodies are not written to stdout.

## Log retention

Journald and Docker json logs rotate locally (operational). The Postgres `audit_event` table and any SIEM copy are the compliance record: 6 years for HIPAA documentation, 5 years for NYDFS 500.6. Chat history is not an audit log; it is purged at 30 days.

Who reviews: the designated security reviewer. Fail-closed and blocked-tool rows within one business day. A weekly sample of allow rows. Quarterly access review of Entra assignments and virtual keys.

## Backups

restic or borg, encrypted, 3-2-1, one copy immutable/offsite. Keys held separately from the repo. Quarterly restore test. RTO/RPO 24h/24h. While the stack is down, work stays in the green lane. Do not fall back to an unredacted tool.

## Egress list

See `deploy/egress-destinations.yaml`. Default is deny. Fixed hosts include `api.anthropic.com`, Entra login hosts, Ubuntu archives, the image registries, and NTP. The Azure OpenAI host is added only when `AZURE_API_HOST` is set to that resource’s `*.openai.azure.com` name. StackJack and Composio hosts are optional and unset. Cloudflared’s `argotunnel` hosts are not allowed until a reviewed non-PHI route exists, and that route still must not target this stack.
