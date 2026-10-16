# Native install runbook (Proxmox, Ubuntu Server)

This is the operator runbook for the Red lane on Cap’s hypervisor. The install is native: one Ubuntu Server virtual machine, Python virtualenvs under `/opt`, systemd units, and no container runtime. `deploy/install.sh` is idempotent. `ansible/site.yml` repeats the same steps. Do not deploy from a pull request; follow `docs/deploy-checklist.md` before any PHI.

PHI users reach Open WebUI over the LAN or WireGuard. They do not reach it through Cloudflare. Cap declined a Cloudflare BAA. `cloudflared` is installed from apt and left disabled.

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

Create one administrative user with SSH key login. Do not enable password SSH. Leave `APPLY_SSH_HARDENING` unset for the first apply so the script does not reload sshd until key login has been tested. The drop-in it installs is `deploy/ssh/99-local-ai.conf` (no root login, no password authentication, no TCP forwarding).

## 3. What the guest must reach during apply

`install.sh --apply` installs apt packages, hashed wheels, the spaCy model, and the local embedding weights. Outbound must work for that run. After apply, UFW default-denies outbound except the owner rules generated from `deploy/egress-destinations.yaml`.

Hosts used at install time, as root: `archive.ubuntu.com`, `security.ubuntu.com`, `pypi.org`, `files.pythonhosted.org`, `dl.cloudsmith.io` (Caddy), `pkg.cloudflare.com` (the cloudflared package, not a tunnel), `github.com` and `release-assets.githubusercontent.com` (the spaCy wheel), `huggingface.co` and the Hugging Face CDN hosts (one download). Time sync uses `time.cloudflare.com` as `systemd-timesync`.

## 4. Configure, then apply

Clone the repository somewhere that is not `/opt/local-ai-stack`. The script creates that path for its own files.

```bash
sudo install -d -m 0755 /opt/src
sudo git clone <repo-url> /opt/src/local-ai-stack
cd /opt/src/local-ai-stack
sudo bash deploy/install.sh --check
```

`--check` only validates the tree. It does not change the host. CI runs the same check.

Set the non-secret values in the environment before the first `--apply`. The ones that change firewall and bind behavior are `VPN_SSH_CIDR` (SSH and 443 from the operator network), `VPN_BIND_IP` (Caddy; default `127.0.0.1`), `AZURE_API_HOST` (the real `*.openai.azure.com` name, only if Foundry will be used), and `WIREGUARD_LISTEN_PORT` if this VM is a WireGuard listener. Copy `config.env.example` into the shell environment or export the variables. `install.sh` does not source a dotenv file.

On the first apply, export the secrets `deploy/write-secret.sh` reads. An empty variable is skipped and does not overwrite a file that is already there. A missing file means that unit cannot authenticate.

| Variable | File written |
|---|---|
| `POSTGRES_PASSWORD` | `/etc/postgres/postgres_password` |
| `LITELLM_MASTER_KEY` | `/etc/litellm/litellm_master_key` |
| `ANTHROPIC_API_KEY` | `/etc/litellm/anthropic_api_key` |
| `AZURE_CLIENT_SECRET` | `/etc/litellm/azure_client_secret` |
| `DATABASE_URL` | `/etc/litellm/database_url` |
| `LITELLM_VIRTUAL_KEY` | `/etc/policy-gateway/litellm_virtual_key` and `/etc/open-webui/litellm_virtual_key` |
| `AUDIT_DATABASE_URL` | `/etc/policy-gateway/audit_database_url` |
| `WEBUI_SECRET_KEY` | `/etc/open-webui/webui_secret_key` |
| `MICROSOFT_CLIENT_SECRET` | `/etc/open-webui/microsoft_client_secret` |

Leave `ANTHROPIC_BAA_ENABLED` unset or `false`. The policy file also defaults the switch off. Do not export a live key from a different Anthropic organization. The check that this key and org are the ZDR org is `docs/baa-zdr-checklist.md`, and it is not done by the installer.

If WireGuard should come up with this apply, install `/etc/wireguard/wg0.conf` at mode `0600` first. The example in `deploy/wireguard/wg0.conf.example` has no private key. Otherwise the unit stays disabled and can be enabled later.

```bash
sudo --preserve-env bash deploy/install.sh --apply
unset POSTGRES_PASSWORD LITELLM_MASTER_KEY ANTHROPIC_API_KEY AZURE_CLIENT_SECRET \
  DATABASE_URL LITELLM_VIRTUAL_KEY AUDIT_DATABASE_URL WEBUI_SECRET_KEY MICROSOFT_CLIENT_SECRET
```

Apply creates a system user with `/usr/sbin/nologin` for each app, a hashed venv, a unit with `ProtectSystem=strict`, `NoNewPrivileges=yes`, `PrivateTmp=yes`, and an empty `CapabilityBoundingSet=` (Caddy is the exception: it needs `CAP_NET_BIND_SERVICE` to bind 443), and credential files mode `0600` loaded with `LoadCredential`. It enables `local-ai-retention.timer`, disables `cloudflared`, and refuses to continue if `/etc/docker/daemon.json` contains `tcp://`.

Re-running `--apply` is the supported way to pick up a new tree. It will not blank a secret whose variable is unset.

## 5. Start, stop, and check

Units are enabled. Start them once the secret files exist:

```bash
sudo systemctl start local-ai-stack.target
sudo systemctl status local-ai-stack.target presidio-analyzer presidio-anonymizer \
  litellm policy-gateway open-webui caddy postgresql
systemctl is-enabled cloudflared   # disabled
sudo ss -lntup
sudo ufw status verbose
```

Expected listeners: Postgres `127.0.0.1:5432`, Presidio analyzer `127.0.0.1:3000`, anonymizer `127.0.0.1:3001`, LiteLLM `127.0.0.1:4000`, policy gateway `127.0.0.1:8088`, Open WebUI `127.0.0.1:8080`, Caddy on `127.0.0.1:443` or on `VPN_BIND_IP:443`. Nothing on `0.0.0.0`. UFW defaults are deny incoming and deny outgoing.

Stop the stack with `sudo systemctl stop local-ai-stack.target`. Leave WireGuard up if that is how you administer the host. A routine stop is not an incident.

Health, from the VM: `curl -fsS http://127.0.0.1:8088/health`. A synthetic prompt check (fixture data only) is item 9 of `docs/deploy-checklist.md`.

Open WebUI is `https://webui.lan.internal` as served by `deploy/Caddyfile`, TLS 1.2 or 1.3, certificate generated on first apply under `/var/lib/local-ai-stack/certs/`. Reach it from the VPN address once `VPN_BIND_IP` is the WireGuard address and apply has been re-run. The SSH drop-in turns off TCP forwarding, so an SSH tunnel is not the access path.

## 6. Routine work

| When | Action |
|---|---|
| Daily | `systemctl list-timers local-ai-retention.timer` shows the chat purge. Fail-closed audit rows are reviewed the same business day. |
| Weekly | The designated reviewer samples allow-rows in `audit_event`. Confirm `cloudflared` is still disabled. |
| Monthly | Read upstream release notes before bumping a hashed lock. `unattended-upgrades` reboots at 03:30 for security updates; the pip locks do not float. |
| Quarterly | Restore test of the encrypted backup. Entra assignment and virtual-key access review. |
| Before any PHI | `docs/deploy-checklist.md` and `docs/baa-zdr-checklist.md`. |
| On change | Re-run `--apply` from a reviewed commit. Config and allowlist changes follow Cap’s POL-CHG-001 and wait for Marko. |

Backups, RTO/RPO (24h/24h), and the rule that a down stack has no unredacted fallback are in `docs/host-hardening.md`.

## 7. Do not

- Do not install Docker or publish a container port. Apply stops if a Docker TCP socket is configured.
- Do not `systemctl enable --now cloudflared`. The shipped ingress is a 404 sink and is not a path to Open WebUI, the gateway, or LiteLLM.
- Do not set `ANTHROPIC_BAA_ENABLED=true` until the BAA/ZDR checklist is signed for this key and organization.
- Do not set `ALLOW_AZURE_AI_THIRD_PARTY` or `FOUNDRY_ABUSE_MONITORING_OPT_OUT` without the written approval the checklist requires.
- Do not put PHI in the git repo, in journald, or in a Proxmox note.
