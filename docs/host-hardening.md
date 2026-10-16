# Host hardening (Ubuntu Server LTS)

`deploy/install.sh --apply` is the idempotent path. `deploy/install.sh --check` only validates the repo (this is what CI runs).

## LUKS

Full-disk encryption at install, or a LUKS volume mounted on `/var/lib/local-ai-stack` before the units start. `deploy/install.sh --apply` runs `scripts/check_luks.py --target /var/lib/local-ai-stack` and stops if that path is not on a LUKS mapping. `--check` only runs the walker’s self-check, so CI does not need an encrypted disk. `install.sh` bind-mounts that tree over `/var/lib/postgresql` so the database is on the same volume. Escrow the passphrase separately from the backup repo. Details: `docs/encrypted-volumes.md`.

## UFW

Default deny incoming and default deny outgoing. Inbound exceptions are SSH and 443 from `VPN_SSH_CIDR`, plus loopback. Outbound allows are owner-matched UFW rules. Ubuntu’s UFW applies those through nftables. systemd `IPAddressAllow` does not accept hostnames, so it is not used for Entra, Anthropic, or Azure. LiteLLM denies every address except `127.0.0.1` and `127.0.0.2`; its off-host HTTP goes to the egress proxy at `127.0.0.1:8889`. The Open WebUI REJECT for LiteLLM is spliced ahead of the stock `-o lo -j ACCEPT` in `before.rules`, because that accept would otherwise pass the loopback packet first. The same splice rejects every uid except `openwebui` to TCP/8088 on `127.0.0.1` and `127.0.0.2`. `scripts/egress_nft.py` states the same gate. `deploy/health-check.sh gateway` probes that port as the `openwebui` uid. `api.anthropic.com` is added for the `litellm` user only when `ANTHROPIC_BAA_ENABLED=true`. PyPI, the spaCy wheel host, and Hugging Face are install-time allows and are removed on the final `host/ufw.sh` run. `egress-proxy.service` allows Entra only from Open WebUI and Anthropic or Azure only from LiteLLM. Apt and MCP go through their own proxy ports, which check the hostname. DNS, NTP, and SIEM stay on their own uids. See `docs/egress-proxy.md`. Optional Azure, DNS, and SIEM hosts are added only when those variables are set. cloudflared is not installed, and the egress list has no Cloudflare tunnel or Cloudflare apt host.

There is no container runtime and no published Docker port. Caddy binds `${VPN_BIND_IP:-127.0.0.1}:443` and needs `CAP_NET_BIND_SERVICE` to do that. Every other unit has an empty `CapabilityBoundingSet=`. The policy gateway allows only `127.0.0.1` and `127.0.0.2`. Open WebUI denies `127.0.0.2`, which is where LiteLLM listens. If a Docker daemon is already on the host and its `daemon.json` contains `tcp://`, apply refuses to continue.

## unattended-upgrades

Security updates install daily. Automatic reboot is 03:30. Python lock bumps are monthly and wait for a review of the release notes. The hashes in `requirements/*.txt` do not float. The spaCy model pin is `en_core_web_lg==3.8.0`.

## CIS-style baseline

- SSH keys only, no root login: `host/ssh/00-local-ai-vpn.conf` (first match wins over `deploy/ssh/99-local-ai.conf`). Reloading sshd is gated by `APPLY_SSH_HARDENING=1` so an apply does not lock the operator out by surprise.
- `qemu-guest-agent` is installed with `guest-exec` and `guest-file` RPCs blocked. Proxmox backups can still freeze the filesystem.
- `auditd`, AppArmor, and a small sysctl drop-in are installed by the script.
- Package set is the list in `deploy/services.yaml` (Python, Postgres, Caddy, WireGuard, UFW, unattended-upgrades, restic, openssl). No container engine and no cloudflared.
- `systemd-timesyncd` for time sync. NTP target in the egress list and in `deploy/systemd/timesyncd.conf.d/local-ai.conf`: `ntp.ubuntu.com`, uid `systemd-timesync`. Not a Cloudflare host.
- WireGuard is installed and left stopped until `/etc/wireguard/wg0.conf` exists (mode 0600, not in git). The example in `deploy/wireguard/` has no private key.
- Journald `SystemMaxFileSize=10M` and `SystemMaxFiles=5`. LiteLLM is `LITELLM_LOG=ERROR`. Open WebUI `GLOBAL_LOG_LEVEL=WARNING` and audit level is `METADATA` so chat bodies are not written to stdout.
- Unattended-upgrades come from `host/apt/52local-ai-unattended`: security origins only, reboot at 03:30.

## Log retention

Journald rotates locally (operational). The Postgres `audit_event` table and any SIEM copy are the compliance record: 6 years for HIPAA documentation, 5 years for NYDFS 500.6. `local-ai-store-purge.timer` deletes `audit_event` rows older than 2190 days and LiteLLM spend-log rows older than 90 days. Chat history is not an audit log; it is purged at 30 days.

Who reviews: the designated security reviewer. Fail-closed and blocked-tool rows within one business day. A weekly sample of allow rows. Quarterly access review of Entra assignments and virtual keys.

## Backups

restic, encrypted, on the LUKS volume at `/var/lib/local-ai-stack/backups/repo`. The password file is `/etc/restic/password`, mode 0600, root-owned, and is not in git. The backup script runs `scripts/check_luks.py` against the repository and refuses to continue when that path is not on dm-crypt. The `backups` Ansible role enables `restic-backup.timer` and `restic-restore-test.timer` only after `backups_password` is provisioned from Vault. Chat snapshots use `--keep-within 30d`. Audit snapshots use `--keep-within 6y`. The previous audit mix (60 monthly snapshots plus 6 yearly snapshots) could retain a full dump for about 12 years, because a six-year-old dump still held rows that were already six years old. `--keep-within 6y` drops every audit snapshot older than six years. `--keep-daily 30` kept thirty daily chat snapshots, and each snapshot still held chats up to 30 days old, so a restore could bring back about 60 days of chat. `--keep-within 30d` caps the snapshot age at 30 days. A snapshot taken on the last day of that window still contains the live chat table, so the oldest chat text in the backup set can be about 60 days old. That overlap is the live 30-day purge plus one snapshot, which is why the window is not longer. The quarterly timer restores the audit snapshot into a throwaway directory and checks a canary. A failed unit starts `restic-failure.service`. The default route writes `journalctl -t local-ai-restic`. `backups_alert_route` may instead be local mail to a local recipient, or an executable hook. The route is not given the password, and the unit denies every network address. Off-host repository URLs and off-host mail are refused: restic has no egress rule. RTO/RPO 24h/24h. While the stack is down, work stays in the green lane. Do not fall back to an unredacted tool.

## Egress list

See `deploy/egress-destinations.yaml`. Default is deny. Steady-state hosts are Entra login (user `openwebui`), Ubuntu archives and `dl.cloudsmith.io` through the apt proxy (users `root` and `_apt`), and NTP (`ntp.ubuntu.com`). LiteLLM reaches Azure OpenAI with an API key when `AZURE_API_HOST` is set, and does not log in at `login.microsoftonline.com`. `api.anthropic.com` is present for `litellm` only when `ANTHROPIC_BAA_ENABLED=true`. PyPI, GitHub, and Hugging Face are present only while `INSTALL_EGRESS=1`, which the final firewall apply clears. The Azure OpenAI host is added only when `AZURE_API_HOST` is set to that resource’s `*.openai.azure.com` name, and only for `litellm`. StackJack and Composio hosts are optional and unset; the policy gateway reaches them only through `127.0.0.1:8891`. There is no cloudflared package, unit, or apt host.
