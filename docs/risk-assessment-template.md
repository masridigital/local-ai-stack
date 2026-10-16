# Risk assessment (Phase 1 baseline)

Written risk assessment for the Red lane, for 45 CFR 164.308(a)(1)(ii)(A), 23 NYCRR 500.9, and 16 CFR 314.4(b). It is the Phase 1 baseline for this stack, in a form the Qualified Individual can re-sign. It does not replace Cap’s enterprise risk analysis. No real PHI was used to write it.

## Phase 1 baseline

- `local-ai-stack` stays on-prem, on the VPN, with native installs (venv and systemd, not containers).
- The identity provider is Microsoft Entra. Zitadel is a fallback only.
- `presidio-redaction-mcp` is hosted in Azure under the Microsoft BAA. It is not this repository.
- The optional Claude second-pass verifier lives in `presidio-redaction-mcp`, not in this stack.

| | |
|---|---|
| System | local-ai-stack, native Ubuntu Server VM on Cap’s Proxmox host |
| Qualified Individual and owner | Joseph Masri (Cap) |
| Prepared | 2026-10-16, from Reggie’s control map and the Phase 1 tree |
| Next review | Annual, and after a material change (new backend, new egress host, tunnel proposal, MCP tool id) |

## Criteria

Score likelihood and impact as low, moderate, or high before the control, then state what is left after the control that actually exists in this repo. A control that is only a document is labeled as such. “High” impact means PHI or customer information leaves Cap’s boundary to a party with no duty to protect it, or the stack is unusable and someone routes around it.

## System and data

Staff with Microsoft Entra and MFA, on the VPN or LAN, use Open WebUI. Caddy terminates TLS on `127.0.0.1` or `VPN_BIND_IP`. The policy gateway calls Presidio, writes a redacted audit row to Postgres, and forwards only allowlisted chat completions to LiteLLM at `127.0.0.2:4000`. `ANTHROPIC_BAA_ENABLED` defaults false. The gateway rejects Anthropic models while the switch is false. The host follows the same switch: `api.anthropic.com` is on the egress proxy for the `litellm` uid only when the switch is true, and `install.sh` writes `/etc/litellm/anthropic_api_key` only then. LiteLLM denies every address except `127.0.0.1` and `127.0.0.2`. Open WebUI is denied `127.0.0.2`. Off-host HTTP from LiteLLM goes through the egress proxy at `127.0.0.1:8889`. LiteLLM may also call a US-region `*.openai.azure.com` host for a first-party `azure/` deployment, using the API key in `/etc/litellm/azure_api_key`. Cloudflare is not on this path. `cloudflared` is not installed.

Data inventory:

| Store | Contents | Leaves the VM? |
|---|---|---|
| Open WebUI SQLite, uploads, vector index | Raw prompts (ePHI) for 30 days, on LUKS | No, if backups of that path follow the 30-day rule |
| `audit_event` | User id, route, decision, entity-type counts, redacted text, policy hash | Only to a SIEM Cap adds later; the row is built to be PHI-free |
| `/etc/<app>` secrets | API keys, Entra secret | No |
| Anthropic | Masked prompt and response, only after the checklist | Yes, under the BAA, ZDR for that org |
| Azure OpenAI | Masked prompt and response | Yes, Microsoft-hosted, US region only |
| Cloudflare | Nothing on the current path | No |
| StackJack, Composio | Not connected. Allowlist empty | No |

## Risks

| ID | Risk | Likelihood / impact before control | Control that exists now | Left over | Owner |
|---|---|---|---|---|---|
| R1 | Raw PHI crosses Cloudflare because TLS terminates there and there is no BAA | High / high if a tunnel publishes Open WebUI | Ingress is VPN/LAN only. `cloudflared` is not installed. The egress list has no Cloudflare host. Test `test_07_and_09_exposure_and_tunnel` | A later change could add an ingress hostname. POL-CHG-001 and Marko are the brake | Joseph Masri |
| R2 | Anthropic receives PHI on a key whose org is not the BAA/ZDR org | High / high | The gateway switch defaults off (`stack/policy.py`, `stack/server.py`). `api.anthropic.com` and the key file exist only when `ANTHROPIC_BAA_ENABLED=true`. The checklist requires the live key and org id. Beta tools, Files, and Batches are rejected. Tests `test_anthropic_key_and_egress_are_gated` and `test_litellm_port_4000_is_gated` | The switch can be flipped in `/etc` without a new commit. The checklist is the procedure that forbids that | Joseph Masri |
| R3 | Foundry processing leaves the United States, or a marketplace model sits outside Microsoft’s BAA | Moderate / high | `azure/` only, US region list, `*.openai.azure.com`, `azure_ai/` default off. Test `test_foundry_region_and_family` | A Global deployment type can still process outside the US even when the resource region is US. The checklist forbids Global | Joseph Masri |
| R4 | Presidio misses an identifier and a no-BAA party receives it | Moderate / high | Recall floors on the synthetic corpus, fail-closed, empty MCP allowlist, residual-risk statement | Free-text clinical context and novel obfuscation. Accepted in `docs/residual-risk.md`. A miss that leaves the boundary is an incident | Joseph Masri |
| R5 | Raw chat on disk or in a Proxmox snapshot | High / moderate (stays inside Cap if LUKS holds) | LUKS, 30-day purge, uploads off | Snapshots and backup keys. Disposal procedure in `docs/retention-disposal.md` | Joseph Masri |
| R6 | No written program, no named QI, no IR clocks | High / moderate (regulatory) | This assessment, `docs/ai-use-policy-template.md`, `docs/incident-response.md` | Counsel still confirms which regimes apply. Training attendance is operational | Joseph Masri |
| R7 | Audit row is tampered with, or a secret lands in a log | Moderate / moderate | Redacted columns, journald cap, gitleaks, `config_hash` of the policy file. Tests `test_06` and `test_08` | Rows are not HMAC-chained. Tamper-evident logging is Phase 2. See `docs/best-practices-compliance.md` | Joseph Masri |
| R8 | StackJack or Composio sees unredacted source data | Low today (not connected) / high if connected without a BAA | `mcp.allowed_upstreams` is empty. Wildcards are rejected | Phase 2 must not add a tool id without a BAA or a written no-PHI scope | Joseph Masri |
| R9 | Operator bypasses a down gateway “just this once” | Moderate / high | Written rule: no unredacted fallback. Fail-closed tests | Depends on the person. Training in the AI-use policy | Joseph Masri |
| R10 | Abuse-monitoring reviewers at Azure see prompts | Low / moderate | Opt-out flag defaults off and the gateway does not send the header. PHI waits on written approval if the flag must be on | Do not guess the flag on | Joseph Masri |

## Risk management decisions (draft, for the QI to accept)

1. PHI users do not cross Cloudflare. That P0 item from the control map is closed for this repo.
2. Anthropic stays off until the key and organization are verified in the console. Cap attested in chat on 2026-10-15 ("BAA has ZDR"). Formal document verification is still pending at Cap's 8 AM review. That attestation is not a substitute for the console check. The gateway, the egress list, and the key file follow the same switch.
3. Foundry, when used, is Azure OpenAI in a US region, Standard or Data Zone (US), never Global, never `azure_ai/`.
4. Residual redaction risk in `docs/residual-risk.md` is accepted for the Red lane. It is not accepted as a reason to feed raw PHI to a no-BAA assistant.
5. Loopback HTTP between units on this VM is accepted for Phase 1. The packets do not leave the host. TLS 1.2+ is required on the Caddy leg and on vendor egress. Revisit if a unit is ever split onto another machine.
6. Annual penetration test and vulnerability scanning at least every six months (314.4(d)) are scheduled work, not a result this repository contains. NYDFS 500.5 scanning, where the entity is in scope, is the same calendar.

## Sign-off

| | Name | Date | Decision |
|---|---|---|---|
| Qualified Individual and owner | Joseph Masri (Cap) | | Accept / accept with changes |
| Counsel | | | Scope confirmed |
| Marko | | | Technical review, before PHI |
