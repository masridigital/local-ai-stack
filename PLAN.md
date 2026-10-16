# local-ai-stack — PLAN

Task: `local-ai-dlp` · Aligned with `/workspace/local-ai-dlp-plan.md` (Red lane) · Status: Draft, pending Marko security review.

## 1. Architecture
```
User (Entra ID SSO + MFA via Conditional Access)
  └─► Open WebUI (OIDC, LAN/VPN only)
        └─► LiteLLM Proxy
              • model allowlist: HIPAA-compliant API (BAA) + Claude via Bedrock or Vertex (BAA)
              • Presidio guardrail: pre_call + post_call, default_on: true
              • custom recognizers: MRN, EHR record IDs, account/bank #s, NPI (synthetic-tested)
              • MCP gateway with pre_mcp_call Presidio guardrail
              • audit: request/spend logs -> Postgres (redacted payloads only) -> SIEM export
        ├─► presidio-analyzer  (ghcr.io/data-privacy-stack/presidio-analyzer:<PINNED_TAG>)
        ├─► presidio-anonymizer (ghcr.io/data-privacy-stack/presidio-anonymizer:<PINNED_TAG>)
        └─► postgres (encrypted volume)
```
All services in Docker Compose on a dedicated VM/VLAN on Cap's on-prem hypervisor. No published ports to the internet; admin UIs reachable only over VPN. Egress allowlist: model API endpoints + Entra only.

## 2. Repo layout (Phase 1 target)
- `docker-compose.yml` — all images pinned by tag **and** digest; no `latest`.
- `litellm/config.yaml` — model_list, guardrails (`presidio`, `mode: [pre_call, post_call]`, `default_on: true`), `pre_mcp_call` guardrail for MCP servers, logging callbacks.
- `presidio/recognizers/*.yaml` — ad-hoc recognizers (MRN, RECORD_ID, ACCOUNT_ID).
- `.env.example` — every secret as a placeholder; real `.env` git-ignored.
- `docs/encrypted-volumes.md` — LUKS / hypervisor-level disk encryption, Postgres volume, backup encryption with separately held keys.
- `docs/entra-sso.md` — app registration, OIDC for Open WebUI + LiteLLM admin UI, CA policy (phishing-resistant MFA for admins).
- `tests/` — fixtures + acceptance tests.

## 3. Phases
| Phase | Scope | Exit |
|---|---|---|
| 1 | Compose skeleton, pinned images, LiteLLM config w/ Presidio pre/post_call default_on, custom recognizers, Postgres audit logging, `.env.example`, docs, synthetic fixtures + test harness | Draft PR, CI green, Marko review |
| 2 | Entra SSO+MFA wiring, MCP gateway + pre_mcp_call, SIEM export, backup/restore scripts | Restore test passes |
| 3 | Deploy on Cap's hypervisor (after Marko CLEAR + Cap open questions answered) | Acceptance tests pass on target |

## 4. Acceptance tests (synthetic data ONLY)
Fixtures in `tests/fixtures/` are generated (Faker + fixed seeds) and labeled `SYNTHETIC`. **No real PHI, client data, or Lumina data — ever.** CI greps for a fixture header and fails if missing.
1. **pre_call redaction:** prompt containing synthetic name, DOB, SSN `000-00-0000`-style invalid numbers, MRN `MRN-SYN-0001234` → upstream mock model receives placeholders only.
2. **post_call redaction:** mock model returns synthetic PHI → client receives masked text.
3. **Custom recognizers:** MRN / RECORD_ID / ACCOUNT_ID fixtures each detected ≥ threshold (start 0.4–0.5); negative fixtures not over-masked.
4. **Fail-closed:** stop presidio-analyzer → LiteLLM request returns error, **mock model receives nothing** (assert zero calls). Same for anonymizer.
5. **pre_mcp_call:** MCP tool call with synthetic PHI args is masked/blocked before reaching mock MCP server.
6. **Audit:** every request writes a log row; row contains no raw fixture PII (grep check).
7. **Exposure:** no service binds 0.0.0.0 on a host-published port except via reverse proxy on LAN interface; compose lint check.
8. **Secrets:** no secrets in repo (gitleaks in CI); compose references env only.
9. **Model allowlist:** request to non-allowlisted model rejected.

## 5. Out of scope / guardrails for builders
No deploy, no merge without Marko review, no real credentials, no public exposure, no real data.
