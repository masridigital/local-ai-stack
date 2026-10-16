# Control traceability (Reggie’s map → this repo)

Reggie’s control map (2026-10-15) scored the draft plans. This table is the same citations, pointed at the Phase 1 tree after Cap’s decisions: native systemd, VPN/LAN only, no Cloudflare on the PHI path, Anthropic switch default off, Foundry limited to Azure OpenAI in US regions. Yellow-lane items live in the other repository; they are listed so a reader of the map can see they are not implemented here.

Status words: **met** (control exists in this repo), **procedure** (this `docs/` set, not a runtime control), **deferred** (named phase or a reason).

| Citation | Requirement | Where it is | Status |
|---|---|---|---|
| 164.308(a)(1)(ii)(A)–(B) | Risk analysis and risk management | `docs/risk-assessment-template.md` | Procedure. QI is Joseph Masri |
| 164.308(a)(1)(ii)(D) | Activity review | `litellm/policy.yaml` `audit_review`; `docs/ai-use-policy-template.md` | Met for cadence. SIEM export is Phase 2 |
| 164.308(a)(3)–(4) | Workforce security, access authorization | `docs/entra-sso.md`, `docs/ai-use-policy-template.md` | Procedure plus Entra. Quarterly review is the procedure |
| 164.308(a)(5) | Security awareness | Training section of `docs/ai-use-policy-template.md` | Procedure. Attendance is operational |
| 164.308(a)(6) | Incident procedures | `docs/incident-response.md` | Procedure, including the 164.402 assessment |
| 164.308(a)(7) | Contingency plan | `docs/host-hardening.md`, `docs/runbook.md` | Met as procedure. RTO/RPO 24h/24h. No unredacted fallback. Restore test is quarterly and not yet a logged result |
| 164.308(a)(8) | Periodic evaluation | Phase 5 in `PLAN.md`; annual QI report in the AI-use policy | Procedure |
| 164.308(b)(1), 164.314(a) | Business associate contracts | `docs/baa-zdr-checklist.md` | Procedure. Cloudflare path removed. StackJack/Composio not connected |
| 164.310(a)–(c) | Facility, workstation | Proxmox host at Cap; Conditional Access compliant device in the AI-use policy | Procedure. Physical room controls are Cap’s, outside this repo |
| 164.310(d) | Device and media disposal | `docs/retention-disposal.md`, `docs/encrypted-volumes.md` | Procedure |
| 164.312(a)(1), (a)(2)(i) | Unique user ID | Entra subject on the request; `user_id` on `audit_event`. Test `test_06_audit_has_user_and_no_raw_phi` | Met |
| 164.312(a)(2)(ii) | Emergency access | `docs/entra-sso.md`, `deploy/break-glass-enable.sh`. Test `test_break_glass_refuses_argv` | Met |
| 164.312(a)(2)(iii) | Automatic logoff | `JWT_EXPIRES_IN=8h` in `docs/entra-sso.md` | Met for the UI session |
| 164.312(a)(2)(iv) | Encryption at rest | LUKS, `docs/encrypted-volumes.md`. Open WebUI data is on that volume | Met |
| 164.312(b) | Audit controls | `postgres/init/001-audit.sql`, `stack/audit.py`. Tests `test_06_*` | Met for redacted rows. HMAC chain deferred to Phase 2 |
| 164.312(c) | Integrity | Hashed requirements, `scripts/generate_sbom.py`, `config_hash` on policy load. CI: gitleaks, bandit, Trivy | Met for supply chain and policy hash. Image digests do not apply; there is no image |
| 164.312(d) | Person or entity authentication | Entra MFA; vendor TLS. Service-token rotation is Phase 2 | Met for users |
| 164.312(e)(1)–(2) | Transmission security | Caddy TLS 1.2+ (`deploy/Caddyfile`); HTTPS egress. Loopback HTTP between units | Met on the wire that leaves the host. Loopback HTTP accepted in the risk assessment |
| 164.316 | Policies, six-year retention | This `docs/` set. `docs/retention-disposal.md` | Procedure |
| 500.2, 500.3 | Cybersecurity program and written policy | `docs/ai-use-policy-template.md`, `docs/host-hardening.md` | Procedure, if the entity is a Covered Entity and not exempt under 500.19 |
| 500.6 | Audit trail | `docs/retention-disposal.md` | Procedure. (a)(2) floor is three years; (a)(1) floor is five; rows are kept six |
| 500.7 | Access privileges | Entra group, quarterly review, empty MCP allowlist | Partial. Annual review procedure is written; the first review is operational |
| 500.8 | Application security | `.github/workflows/ci.yml` (pytest, shellcheck, bandit, gitleaks, Trivy, SBOM) | Met for this in-house gateway |
| 500.9 | Risk assessment | `docs/risk-assessment-template.md` | Procedure |
| 500.11 | Third-party service providers | `docs/baa-zdr-checklist.md` | Procedure. Due-diligence files for each vendor are evidence-pack work, not committed secrets |
| 500.12 | MFA | Entra Conditional Access; hypervisor console is Cap’s | Met for the application. SSH is key-based; VPN MFA is the network gate |
| 500.13 | Asset inventory, retention, disposal | `deploy/services.yaml`, `scripts/generate_sbom.py`, `docs/retention-disposal.md` | Met |
| 500.14 | Monitoring and training | Audit review cadence; training section of the AI-use policy | Partial. Training delivery is operational |
| 500.15 | Encryption of nonpublic information | LUKS and TLS as above | Met, with the loopback note |
| 500.16, 500.17 | Incident response; 72-hour notice | `docs/incident-response.md` | Procedure |
| 314.4(a) | Qualified Individual | Joseph Masri (Cap), named in the AI-use policy and the risk assessment | Procedure |
| 314.4(b) | Written risk assessment | `docs/risk-assessment-template.md` | Procedure |
| 314.4(c)(1) | Access controls | Entra, allowlists, loopback binds | Met |
| 314.4(c)(2) | Data and system inventory | Risk assessment, data inventory section | Procedure |
| 314.4(c)(3) | Encryption in transit and at rest | Same as 164.312(a)(2)(iv) and 164.312(e) | Met, with the loopback note |
| 314.4(c)(4) | Secure development | CI scans above | Met |
| 314.4(c)(5) | MFA | Entra | Met |
| 314.4(c)(6) | Disposal within two years unless an exception applies | `docs/retention-disposal.md`, `docs/disposal-schedule.md` | Met as procedure. Chat is 30 days |
| 314.4(c)(7) | Change management | POL-CHG-001 referenced in the AI-use policy; Marko review | Procedure |
| 314.4(c)(8) | Monitor authorized users | `user_id` on audit rows | Met. Alert transport to a SIEM is Phase 2 |
| 314.4(d) | Testing and monitoring | CI on every push. Annual pen test and six-month scans are scheduled in the risk assessment | Partial. The pen test is not a result in this repo |
| 314.4(e) | Training | AI-use policy | Procedure |
| 314.4(f) | Service-provider oversight | BAA/ZDR checklist | Procedure |
| 314.4(h) | Written incident-response plan | `docs/incident-response.md` | Procedure |
| 314.4(i) | Annual report | AI-use policy, QI report to the evidence pack | Procedure |
| 314.4(j) | FTC notice within 30 days at 500 consumers | `docs/incident-response.md` | Procedure |
| DLP efficacy | Recall floors, fail-closed, residual risk | `litellm/policy.yaml` `recall_floors`; `docs/residual-risk.md`; tests `test_03_*`, `test_04_*` | Met for the synthetic corpus. Not Safe Harbor de-identification |

## Map items that are closed or moved

- Cloudflare seeing raw prompts (control-map P0): closed. No tunnel route. Test `test_07_and_09_exposure_and_tunnel`.
- Open WebUI history not called out: closed as a design item. The directory is on LUKS and purged at 30 days.
- Qualified Individual unnamed: closed. Joseph Masri (Cap).
- Written AI-use policy, risk assessment, IR clocks, disposal: this directory.

## Map items that remain outside this lane

- HMAC-chained audit rows and SIEM export: Phase 2. The policy hash is not that chain.
- A live StackJack or Composio tool: not in `litellm/policy.yaml`. Adding one is a BAA decision, not a docs edit.
- Pen-test evidence, training attendance, and the signed BAA PDF: evidence pack, not the git repo.
