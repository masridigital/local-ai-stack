# Encrypted volumes

The VM disk is LUKS at install, or a LUKS volume is mounted at `/var/lib/local-ai-stack` before Docker starts. Keys and passphrases are escrowed outside this host (vault or sealed envelope), not next to the backup set.

| Path | Contents | Class |
|---|---|---|
| `/var/lib/local-ai-stack/postgres` | LiteLLM database and `audit_event` | Redacted audit metadata; still on LUKS |
| `/var/lib/local-ai-stack/webui` | Open WebUI SQLite, chat history, uploads, vector index | ePHI. Raw prompts live here until the 30-day purge |
| `/var/lib/local-ai-stack/backups` | restic or borg repository cache | Encrypted again by the backup tool |
| `/var/lib/local-ai-stack/certs` | LAN TLS key | Private key mode 0600 |
| `/etc/local-ai-stack/secrets` | Docker secret files | Mode 0700 directory, 0600 files, root |

Open WebUI’s search index is inside the webui directory. There is no external embedding API. Uploads are disabled; the directory is still encrypted because a future admin toggle must not land files on an open disk.

Postgres is not given a host port. Backup dumps are taken from the encrypted volume and written only into the encrypted backup repo. Restore is a quarterly test. RTO and RPO for this single-user stack are 24 hours.

Decommissioning a disk or snapshot is crypto-erase: destroy the LUKS key and the backup key that can open it. See `docs/disposal-schedule.md`.
