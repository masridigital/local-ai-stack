# Retention and disposal

Policy for data this stack actually stores. The operational table is `docs/disposal-schedule.md`. The timer that deletes chat rows is `local-ai-retention.timer` (`deploy/systemd/local-ai-retention.timer`), which runs `stack/retention.py` against the Open WebUI database. This document is the reason for those periods. It is not a determination that every Cap system is a HIPAA covered entity, a DFS Covered Entity, or an FTC financial institution. Counsel decides scope. Joseph Masri (Cap) owns the schedule for this system as Qualified Individual.

## What the citations require

| Duty | Citation | What it actually says | What this stack does |
|---|---|---|---|
| Security documentation | [45 CFR 164.316(b)(2)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.316) | Keep the written policies and procedures, and written records of required actions, activities, or assessments, for six years from creation or from the date last in effect, whichever is later | Keep this `docs/` set, the incident write-ups, the risk assessment, and the BAA/ZDR evidence pack for six years |
| Audit controls | [45 CFR 164.312(b)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.312) | Implement mechanisms that record and examine activity in systems that contain or use ePHI. The rule does not set a six-year log clock | Redacted `audit_event` rows are the mechanism. They are kept six years so the documentation of the safeguard outlives the 164.316 period. Raw prompts are not part of that record |
| NYDFS audit trail | [23 NYCRR 500.6(b)](https://www.dfs.ny.gov/system/files/documents/2026/07/NYCRR-part-500-Cybersecurity-Regulation.pdf) | Records that reconstruct material financial transactions (500.6(a)(1)) are kept at least five years. Audit trails designed to detect and respond to cybersecurity events (500.6(a)(2)) are kept at least three years | `audit_event` is an (a)(2) trail. Six years covers both floors. Confirm 500.19 exemptions before treating 500.6 as applicable |
| NYDFS disposal | 23 NYCRR 500.13(b) | Periodically dispose of nonpublic information that is no longer necessary for business operations or another legitimate business purpose, with stated exceptions | Chat content is disposed of on the 30-day timer. Backup media that held it is destroyed with the key |
| FTC disposal | [16 CFR 314.4(c)(6)](https://www.ecfr.gov/current/title-16/chapter-I/subchapter-C/part-314/section-314.4) | Dispose of customer information no later than two years after the last date it was used for the product or service, unless it is necessary for business operations or another legitimate purpose, required by law or regulation, or cannot reasonably be targeted. Review the policy so data is not kept without a reason | Chat, uploads, and the local vector index are deleted at 30 days, inside the two-year limit. The six-year audit retention is the “required by law / legitimate investigation” exception, and it applies to redacted rows, not to raw chat |

## Schedule

| Asset | Keep | Then | Why a longer period is not used |
|---|---|---|---|
| Open WebUI chats, uploads, vector index | 30 days (`CHAT_RETENTION_DAYS`) | `local-ai-retention.timer` deletes the rows. Uploads are disabled; the file table is still purged | Raw prompts are ePHI on the LUKS volume. They are not the audit trail |
| Presidio analyzer and anonymizer | Nothing. The venvs are stateless | No action | No customer information |
| Policy-gateway and LiteLLM journald | `SystemMaxFileSize=10M`, `SystemMaxFiles=5`, no bodies | Rotation drops them | Operational only |
| `audit_event` and any SIEM copy | 6 years | Delete, or crypto-erase the backup set that holds them | Longer than 164.316 and longer than both 500.6 floors. Do not add a raw-prompt column to meet this |
| Backups | Same as the data they contain | `restic forget` for paths that can be selected; otherwise destroy the restic or borg key | A backup of chat must not outlive the 30-day rule where the tool can select paths |
| VM disks, Proxmox snapshots, decommissioned volumes | Until the host is retired or the snapshot expires | Crypto-erase by destroying the LUKS key. Do not hand the disk on, and do not leave a Proxmox snapshot that can open it | 500.13 and 314.4(c)(6) |
| `/etc/<app>` credential files | Until rotated | Revoke at the vendor, then delete the file. Virtual-key rotation is a Phase 2 control (90 days once that work lands) | A deleted file is not a revocation |

Synthetic fixtures in `tests/fixtures/` are fake by construction (header `SYNTHETIC — FAKE DATA — NOT REAL PERSONS`, Faker seed 4242). They are source, not customer information, and they are not purged on the chat timer.

## How disposal is done

1. Chat and file rows: the daily timer. `stack/retention.py` deletes by timestamp and prints counts only.
2. A retired LUKS volume or Proxmox disk: destroy the passphrase and the key escrow copy. Deleting the VM in the Proxmox UI is not disposal if a snapshot or backup still has the header key.
3. A retired backup repository: `restic forget --prune` for data inside the retention window, then destroy the repository key for media that cannot be wiped.
4. A rotated secret: revoke it, delete the mode-0600 file, and do not leave the old value in shell history. `deploy/write-secret.sh` prints nothing.

There is no `shred` step on the LUKS volume. Crypto-erase is the disposal method for that media. There is no CI job that deletes fixtures; they are not customer data.

## Exceptions

A longer period requires a written reason, the Qualified Individual’s approval (Joseph Masri), and a `config_change` or evidence-pack note. “We might want to look at it” is not a reason. Extending chat retention past 30 days also has to be changed in `litellm/policy.yaml` (`chat_retention_days`) and redeployed; the timer reads `CHAT_RETENTION_DAYS`.

Review this schedule at least annually with the 314.4(i) report, and whenever a new store is added (a SIEM, a snapshot job, an MCP audit table).
