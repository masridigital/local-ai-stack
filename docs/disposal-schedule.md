# Disposal schedule

FTC Safeguards 16 CFR 314.4(c)(6) expects customer information to be disposed of within two years of last use unless a longer period is required. HIPAA documentation is kept six years (164.316). NYDFS audit trails follow the Covered Entity’s 500.6 period, tracked here as five years. Chat content is not that audit trail.

| Asset | Keep | Then |
|---|---|---|
| Open WebUI chats, uploads, vector index | 30 days (`CHAT_RETENTION_DAYS`, daily `local-ai-retention.timer`) | Delete the rows. `ENABLE_KNOWLEDGE_FILE_RETENTION` is false, so removed files are deleted with their embeddings |
| Presidio | Nothing. The containers are stateless | No action |
| Policy-gateway / LiteLLM stdout | Docker json logs, 10m x 5 files, no bodies | Rotate out |
| `audit_event` and SIEM copy | 6 years HIPAA documentation / 5 years NYDFS, whichever the record requires | Delete or crypto-erase the backup set that holds them |
| Backups | Same as the data they contain; chat snapshots should follow the 30-day rule where the tool can select paths | Destroy the restic/borg key to crypto-erase media that cannot be wiped |
| VM disks, decommissioned volumes, old snapshots | Until the host is retired or the snapshot expires | Crypto-erase by destroying the LUKS key. Do not hand a disk on without that step |
| Docker secrets and Entra client secrets | Until rotated (virtual keys: 90 days once Phase 2 rotation is in place) | Revoke in the vault and delete the secret file |

The 6-year and 5-year periods apply to the security documentation and the redacted audit trail, not to raw chat. Raw chat is disposed of on the 30-day timer because it is ePHI we do not need to keep for the audit.
