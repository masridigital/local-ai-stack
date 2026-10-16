# Disposal schedule

FTC Safeguards 16 CFR 314.4(c)(6) expects customer information to be disposed of within two years of last use unless a longer period is required. HIPAA documentation is kept six years (164.316). NYDFS audit trails follow the Covered Entity’s 500.6 period, tracked here as five years. Chat content is not that audit trail.

| Asset | Keep | Then |
|---|---|---|
| Open WebUI chats, uploads, vector index | 30 days (`CHAT_RETENTION_DAYS`, daily `local-ai-retention.timer`) | Delete the rows. `ENABLE_KNOWLEDGE_FILE_RETENTION` is false, so removed files are deleted with their embeddings |
| Presidio | Nothing. The venvs are stateless | No action |
| Policy-gateway / LiteLLM journald | `SystemMaxFileSize=10M`, `SystemMaxFiles=5`, no bodies | Rotate out |
| `audit_event` and SIEM copy | 6 years HIPAA documentation / 5 years NYDFS, whichever the record requires | `local-ai-store-purge.timer` deletes Postgres rows older than 2190 days. The table stays on the LUKS volume. Crypto-erase the backup set that holds older copies |
| LiteLLM spend logs | 90 days. Prompts are not stored | The same timer deletes `LiteLLM_SpendLogs` rows older than 90 days. The database stays on the LUKS volume |
| Backups | Chat snapshots (`ephi`) are `--keep-within 30d`. Audit snapshots are `--keep-within 6y`. A snapshot still holds the live table from the day it was taken, so the oldest chat text can be about 60 days old and a full audit dump is capped at six years of snapshots | Destroy the restic password at `/etc/restic/password` to crypto-erase media that cannot be wiped |
| VM disks, decommissioned volumes, old snapshots | Until the host is retired or the snapshot expires | Crypto-erase by destroying the LUKS key. Do not hand a disk on without that step |
| `/etc/<app>` credential files and Entra client secrets | Until rotated (virtual keys: 90 days once Phase 2 rotation is in place) | Revoke in the vault and delete the secret file |

The 6-year and 5-year periods apply to the security documentation and the redacted audit trail, not to raw chat. Raw chat is disposed of on the 30-day timer because it is ePHI we do not need to keep for the audit.
