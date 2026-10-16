# Encrypted volumes

The VM disk is LUKS at install, or a LUKS volume is mounted at `/var/lib/local-ai-stack` before the units start. `deploy/install.sh --apply` verifies that path with `scripts/check_luks.py --target` and refuses to continue when the walker finds no `crypt` ancestor. `deploy/install.sh` bind-mounts `/var/lib/local-ai-stack/postgres` onto `/var/lib/postgresql` so the apt Postgres cluster is on that volume. Keys and passphrases are escrowed outside this host (vault or sealed envelope), not next to the backup set.

| Path | Contents | Class |
|---|---|---|
| `/var/lib/local-ai-stack/postgres` | LiteLLM database and `audit_event` | Redacted audit metadata; still on LUKS |
| `/var/lib/local-ai-stack/webui` | Open WebUI SQLite, chat history, uploads, vector index, local embedding cache | ePHI. Raw prompts live here until the 30-day purge |
| `/var/lib/local-ai-stack/backups` | local restic repository | Encrypted again by restic. Password is `/etc/restic/password`, mode 0600, root |
| `/var/lib/local-ai-stack/certs` | LAN TLS key | Private key mode 0600 |
| `/etc/open-webui`, `/etc/litellm`, `/etc/policy-gateway`, `/etc/postgres` | Credential files | Mode 0700 directory, 0600 files, root. Loaded with `LoadCredential` |

Open WebUI’s search index is inside the webui directory. There is no external embedding API at runtime. The MiniLM weights are fetched once during apply, as root, into `HF_HOME` on this volume. Uploads are disabled; the directory is still encrypted because a future admin toggle must not land files on an open disk.

Postgres listens on `127.0.0.1` only. Backup dumps are taken from the encrypted volume and written only into the local restic repository on that volume. `restic-restore-test.timer` restores the audit snapshot quarterly into `/var/lib/local-ai-stack/backups/restore-test` and checks a canary. It does not restore onto the live data directory. RTO and RPO for this single-user stack are 24 hours.

Decommissioning a disk or snapshot is crypto-erase: destroy the LUKS key and the backup key that can open it. See `docs/disposal-schedule.md`.
