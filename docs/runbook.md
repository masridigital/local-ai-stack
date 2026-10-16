# Native install runbook (Phase 1 baseline)

This is the Phase 1 operator runbook for the Red lane on Cap’s hypervisor. The install is native: one Ubuntu Server virtual machine, Python virtualenvs under `/opt`, systemd units, and no container runtime. `deploy/install.sh` is idempotent. `ansible/site.yml` repeats the same steps. Do not deploy from a pull request; follow `docs/deploy-checklist.md` before any PHI.

Phase 1 decisions this runbook follows:

- `local-ai-stack` stays on-prem, on the VPN, with native installs.
- The identity provider is Microsoft Entra. Zitadel is a fallback only, not the path this runbook configures.
- `presidio-redaction-mcp` is hosted in Azure under the Microsoft BAA. It is not installed by `deploy/install.sh`.
- The optional Claude second-pass verifier lives in `presidio-redaction-mcp`, not on this VM.

PHI users reach Open WebUI over the LAN or WireGuard. They do not reach it through Cloudflare. Cap declined a Cloudflare BAA. `cloudflared` is not installed: apply removes the package, the unit, the apt list, and `/etc/cloudflared` if a previous image left them.

## 1. Proxmox virtual machine

Create a virtual machine, not an LXC container. A container shares the host kernel and will not give this stack its own full-disk LUKS volume.

- Guest: Ubuntu Server 24.04 LTS (the current LTS this repo’s CI runs on).
- Firmware: OVMF (UEFI). SeaBIOS also works with the installer recipe below.
- Machine: q35. Disk bus: VirtIO SCSI. NIC: VirtIO.
- Network: one NIC on the private VLAN bridge. Do not attach a public bridge and do not assign a public address. Management and PHI access are on that VLAN or on WireGuard.
- Starting size for a single-user stack: 4 vCPU, 8 GB RAM, 64 GB disk. The pinned spaCy model (`en_core_web_lg==3.8.0`) and the one-time local embedding download are the reason for the RAM. Increase the disk if restic snapshots will live on this volume.
- Do not put the LUKS passphrase, an API key, or a cloud-init password in the Proxmox VM notes, a snippet, or the backup of `/etc/pve`.

## 2. Install Ubuntu with encryption

Use the Ubuntu Server installer. On the storage screen choose the guided layout that uses LVM and encryption, and encrypt the whole disk. Escrow the passphrase in the vault or a sealed envelope, separate from the backup set and from the Proxmox host. Details of the paths that must sit on that volume are in `docs/encrypted-volumes.md`.

If the disk was installed without encryption, stop and add a LUKS volume mounted at `/var/lib/local-ai-stack` before `install.sh --apply`. The script bind-mounts `/var/lib/local-ai-stack/postgres` onto `/var/lib/postgresql`.

Create one administrative user with SSH key login. Do not enable password SSH. Leave `APPLY_SSH_HARDENING` unset for the first apply so the script does not reload sshd until key login has been tested. The drop-ins are `host/ssh/00-local-ai-vpn.conf` and `deploy/ssh/99-local-ai.conf`: no root login, no password authentication, and local TCP forwarding only to `127.0.0.2:4000`. That forward is not the PHI access path.

## 3. What the guest must reach during apply

`install.sh --apply` installs apt packages, hashed wheels, the spaCy model, and the local embedding weights. Outbound must work for that run. After apply, UFW default-denies outbound except the owner rules generated from `deploy/egress-destinations.yaml`.

Hosts used at install time, as root: `archive.ubuntu.com`, `security.ubuntu.com`, `pypi.org`, `files.pythonhosted.org`, `dl.cloudsmith.io` (Caddy), `github.com` and `release-assets.githubusercontent.com` (the spaCy wheel), `huggingface.co`, `cdn-lfs.huggingface.co`, and `cas-bridge.xethub.hf.co` (one download). PyPI, GitHub, and Hugging Face are install-time allows and are removed on the final firewall apply. Time sync is `systemd-timesyncd` against `ntp.ubuntu.com` (`deploy/systemd/timesyncd.conf.d/local-ai.conf`). There is no Cloudflare apt host and no `time.cloudflare.com`.

## 4. Configure, then apply

Clone the repository somewhere that is not `/opt/local-ai-stack`. The script creates that path for its own files.

```bash
sudo install -d -m 0755 /opt/src
sudo git clone <repo-url> /opt/src/local-ai-stack
cd /opt/src/local-ai-stack
sudo bash deploy/install.sh --check
```

`--check` only validates the tree. It does not change the host. CI runs the same check.

Set the non-secret values in the environment before the first `--apply`. The ones that change firewall and bind behavior are `VPN_SSH_CIDR` (SSH and 443 from the operator network), `VPN_BIND_IP` (Caddy; default `127.0.0.1`), `AZURE_API_HOST` (one label whose name includes a US region from `litellm/policy.yaml` and ends in `.openai.azure.com`, only if Foundry will be used), and `WIREGUARD_LISTEN_PORT` if this VM is a WireGuard listener. Copy `config.env.example` into the shell environment or export the variables. `install.sh` does not source a dotenv file.

On the first apply, `host/secrets/populate.sh` writes root-owned mode-0600 files. An empty variable is skipped and does not overwrite a file that is already there. Generated values are created when the file is missing. There is no Azure client secret on the LiteLLM unit.

| Variable | File written |
|---|---|
| `POSTGRES_PASSWORD` | `/etc/postgres/postgres_password` (generated if unset and missing) |
| (generated) | `/etc/litellm/litellm_master_key`, `/etc/open-webui/webui_secret_key`, `/etc/open-webui/webui_admin_password`, and the gateway client key under `/etc/policy-gateway` and `/etc/open-webui` |
| `AZURE_API_KEY` | `/etc/litellm/azure_api_key` |
| `DATABASE_URL` | `/etc/litellm/database_url` (built from the Postgres password when unset) |
| `LITELLM_VIRTUAL_KEY` | `/etc/policy-gateway/litellm_virtual_key` |
| `AUDIT_DATABASE_URL` | `/etc/policy-gateway/audit_database_url` |
| `MICROSOFT_CLIENT_SECRET` | `/etc/open-webui/microsoft_client_secret` |
| `ANTHROPIC_API_KEY` | `/etc/litellm/anthropic_api_key`, and only when `ANTHROPIC_BAA_ENABLED=true`. Otherwise apply deletes that file |

Leave `ANTHROPIC_BAA_ENABLED` unset or `false`. The policy file also defaults the switch off. Do not export a live key from a different Anthropic organization. The check that this key and org are the ZDR org is `docs/baa-zdr-checklist.md` and item 5 of `docs/deploy-checklist.md`. The installer does not check the live org. When the switch is true, apply also adds `api.anthropic.com` for the `litellm` user on the egress proxy.

If WireGuard should come up with this apply, install `/etc/wireguard/wg0.conf` at mode `0600` first. The example in `deploy/wireguard/wg0.conf.example` has no private key. Otherwise the unit stays disabled and can be enabled later.

```bash
sudo --preserve-env bash deploy/install.sh --apply
unset POSTGRES_PASSWORD ANTHROPIC_API_KEY AZURE_API_KEY \
  DATABASE_URL LITELLM_VIRTUAL_KEY AUDIT_DATABASE_URL MICROSOFT_CLIENT_SECRET
```

Apply creates a system user with `/usr/sbin/nologin` for each app, a hashed venv, a unit with `ProtectSystem=strict`, `NoNewPrivileges=yes`, `PrivateTmp=yes`, and an empty `CapabilityBoundingSet=` (Caddy is the exception: it needs `CAP_NET_BIND_SERVICE` to bind 443), and credential files mode `0600` loaded with `LoadCredential`. It enables `local-ai-retention.timer` and `local-ai-store-purge.timer`, removes `cloudflared` if present, and refuses to continue if `/etc/docker/daemon.json` contains `tcp://`.

Re-running `--apply` is the supported way to pick up a new tree. It will not blank a secret whose variable is unset.

## 5. Start, stop, and check

Units are enabled. Start them once the secret files exist:

```bash
sudo systemctl start local-ai-stack.target
sudo systemctl status local-ai-stack.target presidio-analyzer presidio-anonymizer \
  litellm policy-gateway open-webui caddy postgresql egress-proxy
sudo ss -lntup
sudo ufw status verbose
```

Expected listeners: Postgres `127.0.0.1:5432`, Presidio analyzer `127.0.0.1:3000`, anonymizer `127.0.0.1:3001`, LiteLLM `127.0.0.2:4000`, policy gateway `127.0.0.1:8088`, Open WebUI `127.0.0.1:8080`, the egress proxy on `127.0.0.1:8888` through `127.0.0.1:8891`, and Caddy on `127.0.0.1:443` or on `VPN_BIND_IP:443`. Nothing on `0.0.0.0`. Open WebUI is denied `127.0.0.2`. UFW defaults are deny incoming and deny outgoing. `api.anthropic.com` is absent unless `ANTHROPIC_BAA_ENABLED=true`.

Stop the stack with `sudo systemctl stop local-ai-stack.target`. Leave WireGuard up if that is how you administer the host. A routine stop is not an incident.

Gateway health, from the VM as root: `sudo deploy/health-check.sh gateway`. That runs `curl` as the `openwebui` uid, which is the only uid allowed to open TCP/8088. The LiteLLM `:4000` probe stays root because that uid is rejected from port 4000. A synthetic prompt check (fixture data only) is item 10 of `docs/deploy-checklist.md`.

Open WebUI is `https://webui.lan.internal` as served by `deploy/Caddyfile`, TLS 1.2 or 1.3, certificate generated on first apply under `/var/lib/local-ai-stack/certs/`. Reach it from the VPN address once `VPN_BIND_IP` is the WireGuard address and apply has been re-run. SSH local forwarding is limited to `127.0.0.2:4000` and is not the access path.

## 6. Routine work

| When | Action |
|---|---|
| Daily | `systemctl list-timers local-ai-retention.timer local-ai-store-purge.timer` shows the chat purge and the audit/spend purge. Fail-closed audit rows are reviewed the same business day. |
| Weekly | The designated reviewer samples allow-rows in `audit_event`. Confirm `cloudflared` is not installed. |
| Monthly | Read upstream release notes before bumping a hashed lock. `unattended-upgrades` reboots at 03:30 for security updates; the pip locks do not float. |
| Quarterly | Restore test of the encrypted backup. Entra assignment and virtual-key access review. |
| Before any PHI | `docs/deploy-checklist.md` and `docs/baa-zdr-checklist.md`. |
| On change | Re-run `--apply` from a reviewed commit. Config and allowlist changes follow Cap’s POL-CHG-001 and wait for Marko. |

Backups, RTO/RPO (24h/24h), and the rule that a down stack has no unredacted fallback are in `docs/host-hardening.md`.

## 7. Do not

- Do not install Docker or publish a container port. Apply stops if a Docker TCP socket is configured.
- Do not install `cloudflared`. This tree has no tunnel unit and no ingress hostname for Open WebUI, the gateway, or LiteLLM.
- Do not set `ANTHROPIC_BAA_ENABLED=true` until the BAA/ZDR checklist is signed for this key and organization.
- Do not set `ALLOW_AZURE_AI_THIRD_PARTY` or `FOUNDRY_ABUSE_MONITORING_OPT_OUT` without the written approval the checklist requires.
- Do not put PHI in the git repo, in journald, or in a Proxmox note.
