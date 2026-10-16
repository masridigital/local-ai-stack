# AI-use policy (Phase 1 baseline)

Phase 1 baseline for the local-ai-stack Red lane. Copy forward when the system changes; do not invent a second production path beside it. Not legal advice. Counsel confirms whether HIPAA, 23 NYCRR 500, and the FTC Safeguards Rule apply to a given entity. Marko reviews technical changes before deploy.

Phase 1 decisions:

- `local-ai-stack` stays on-prem, on the VPN, with native installs.
- The identity provider is Microsoft Entra. Zitadel is a fallback only.
- `presidio-redaction-mcp` is hosted in Azure under the Microsoft BAA.
- The optional Claude second-pass verifier lives in `presidio-redaction-mcp`, not in this stack.

| | |
|---|---|
| System owner | Joseph Masri (Cap) |
| Qualified Individual (16 CFR 314.4(a)) | Joseph Masri (Cap) |
| Security reviewer | Marko, before merge of a control change and before the first deploy |
| Status | Phase 1 baseline. PHI use waits on `docs/deploy-checklist.md` |

The Qualified Individual oversees this information-security program, keeps the written risk assessment (`docs/risk-assessment-template.md`), and makes the written report at least annually under [16 CFR 314.4(i)](https://www.ecfr.gov/current/title-16/chapter-I/subchapter-C/part-314/section-314.4). If a DFS Covered Entity names a CISO under 23 NYCRR 500.4, that designation is a separate legal appointment. This policy does not silently merge the two roles.

## 1. What people may use

Staff reach Open WebUI over the LAN or WireGuard. The identity provider is Microsoft Entra, with MFA and an 8-hour session. Zitadel is a fallback only and is not the sign-in path for this baseline. The path is in `PLAN.md` and `docs/runbook.md`.

| Path | What it is | PHI |
|---|---|---|
| Red lane, this repo | Open WebUI → policy gateway → Presidio → LiteLLM → Anthropic (only after the BAA/ZDR checklist, and only while `ANTHROPIC_BAA_ENABLED=true` on the gateway and the host) or Azure OpenAI in a US region. On-prem, VPN, native install | Allowed only for people Cap has authorized, and only after the deploy checklist is signed |
| Yellow lane, `presidio-redaction-mcp` | Hosted in Azure under the Microsoft BAA. Presidio masks before a no-BAA assistant sees a result. The optional Claude second-pass verifier lives in that repo | Do not paste raw PHI into Grok Bot or any assistant that has no BAA. The Azure host is under Microsoft’s BAA; the no-BAA assistant is not |
| Anything else (consumer Claude, public chat tools, a Cloudflare hostname, a personal API key) | Not this system | Prohibited for PHI and for nonpublic personal information |

Cloudflare Tunnel is not an access method for this UI. Cap declined a Cloudflare BAA. `cloudflared` is not installed.

## 2. Models and switches

- Anthropic: the models named in `litellm/policy.yaml`. `ANTHROPIC_BAA_ENABLED` stays false until `docs/baa-zdr-checklist.md` records that this API key and organization are the BAA organization and that ZDR is on for that organization. Cap attested in chat on 2026-10-15 ("BAA has ZDR"). Formal document verification is still pending at Cap's 8 AM review. The installer does not check the live org. While the switch is false, the gateway rejects Anthropic models, the egress proxy does not allow `api.anthropic.com`, and apply does not leave an Anthropic key file. LiteLLM listens on `127.0.0.2:4000`. Open WebUI cannot open that address.
- Foundry means Azure OpenAI, Microsoft-hosted, provider `azure/`, in a US region listed in `litellm/policy.yaml`, family `gpt-4.1` or `gpt-4o` (including the mini and nano ids in that file). `azure_ai/` marketplace models stay off. Abuse-monitoring opt-out stays off unless Cap already has written approval.
- Bedrock, Vertex, streaming, Anthropic beta headers, and server-side tools (web search, web fetch, code execution, computer use, Files, Batches) are rejected.

## 3. Handling rules

1. A prompt that may contain PHI stays on this stack, on the VPN, and on an allowlisted backend. It does not go through Cloudflare.
2. Presidio runs before and after the model. If the analyzer or anonymizer fails, times out, or returns malformed data, the request stops. Nobody sets a bypass for a deadline.
3. Open WebUI stores the raw prompt on the LUKS volume for 30 days. That copy is ePHI inside Cap’s boundary. It is not a redacted record. Do not export chats.
4. Logs and the Postgres audit store metadata and redacted text. Do not paste a prompt into Slack, a ticket, or journald to “show the bug.”
5. Tests and fixtures use the synthetic set only (`SYNTHETIC — FAKE DATA — NOT REAL PERSONS`). No real PHI, client data, or Lumina data in the repo or CI.
6. MCP upstreams are empty. StackJack and Composio are not turned on by this policy. They see unredacted source data if they are ever connected; that needs a BAA or a written no-PHI scope before a tool id is added.

## 4. Access

- Unique Entra accounts. No shared daily admin password. Break-glass is `docs/entra-sso.md` and `deploy/break-glass-enable.sh` (secret from a file, two people, recorded as `config_change`).
- Who may use the Red lane with PHI is an Entra group Cap names. Joiner access is granted by that group. Leaver access is removed the same day. The designated reviewer checks assignments and virtual keys quarterly.
- Admins (host group, LiteLLM master key) use a phishing-resistant MFA method.
- Workstation rule: a managed device that meets the Conditional Access compliant-device control. Personal browsers pointed at a public hostname are not a path, because there is no public hostname.

## 5. Training

Before first use, and yearly after that, each person who can reach Open WebUI is shown:

- what may be pasted (Red lane only, after the checklist);
- that the Yellow lane and any no-BAA assistant are never for raw PHI;
- that a suspected miss is reported the same day to the Qualified Individual, and is not “fixed” by sending the prompt somewhere else;
- that chat history is ePHI and is not forwarded.

The Qualified Individual keeps the attendance note with the six-year documentation set. This closes the training gap called out in the control map (164.308(a)(5), 314.4(e), 500.14) as a procedure. Delivery is an operational task, not a software control.

## 6. Monitoring and change

- Fail-closed and blocked-tool rows: one business day. Allow-row sample: weekly. Access review: quarterly.
- Alert material is the audit row (user id, decision, entity types, no raw identifiers). A SIEM export is Phase 2.
- Changes to `litellm/policy.yaml`, the recognizers, the egress list, or an Anthropic/Foundry switch follow POL-CHG-001 and wait for Marko. The gateway records a `config_change` row with a SHA-256 of the policy file.

## 7. Incidents, retention, review

Incidents follow `docs/incident-response.md` (164.402 assessment, NYDFS 72-hour determination, FTC 30-day determination). Retention and disposal follow `docs/retention-disposal.md`.

The Qualified Individual reviews this policy at least annually and writes the 314.4(i) report to the evidence pack. A quarterly look is the Phase 5 rhythm in `PLAN.md`. Violations are access revocation plus Cap’s HR process.

## Adoption

| | Name | Date |
|---|---|---|
| Qualified Individual and owner | Joseph Masri (Cap) | |
| Counsel (scope of HIPAA / NYDFS / FTC) | | |
| Marko (technical review before first PHI use) | | |
