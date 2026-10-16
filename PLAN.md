# local-ai-stack — PLAN

Task: `local-ai-dlp` · Aligned with `/workspace/local-ai-dlp-plan.md` (Red lane) · Status: Draft, pending Marko security review.

## 1. Architecture
```
User (Entra ID SSO + MFA via Conditional Access)
  └─► Open WebUI (OIDC, LAN/VPN only)
        └─► LiteLLM Proxy
              • model allowlist: anthropic/claude-* ONLY, via Anthropic Claude API directly under Cap's BAA (key via env)
              • Presidio guardrail: pre_call + post_call, default_on: true
              • custom recognizers: MRN, EHR record IDs, account/bank #s, NPI (synthetic-tested)
              • MCP gateway with pre_mcp_call Presidio guardrail
              • audit: request/spend logs -> Postgres (redacted payloads only) -> SIEM export
        ├─► presidio-analyzer  (ghcr.io/data-privacy-stack/presidio-analyzer:<PINNED_TAG>)
        ├─► presidio-anonymizer (ghcr.io/data-privacy-stack/presidio-anonymizer:<PINNED_TAG>)
        └─► postgres (encrypted volume)
```
All services in Docker Compose on a dedicated VM/VLAN on Cap's on-prem hypervisor. Exposure only via Cloudflare Tunnel + Access (outbound-only, no inbound ports); only redacted data may cross Cloudflare (no BAA); admin UIs reachable only over VPN. Egress allowlist: api.anthropic.com + Entra only.

## 2. Repo layout (Phase 1 target)
- `docker-compose.yml` — all images pinned by tag **and** digest; no `latest`.
- `litellm/config.yaml` — model_list, guardrails (`presidio`, `mode: [pre_call, post_call]`, `default_on: true`), `pre_mcp_call` guardrail for MCP servers, logging callbacks.
- `presidio/recognizers/*.yaml` — ad-hoc recognizers (MRN, RECORD_ID, ACCOUNT_ID).
- `.env.example` — every secret as a placeholder; real `.env` git-ignored.
- `docs/encrypted-volumes.md` — LUKS / hypervisor-level disk encryption, Postgres volume, backup encryption with separately held keys.
- `docs/entra-sso.md` — app registration, OIDC for Open WebUI + LiteLLM admin UI, CA policy (phishing-resistant MFA for admins).
- `tests/` — fixtures + acceptance tests.

## 3. Phases (full build — HIPAA / NYDFS 500 / FTC Safeguards, not an MVP)
| Phase | Scope | Exit |
|---|---|---|
| 1 | Compose (pinned tag+digest), LiteLLM w/ Presidio pre/post_call default_on (primary control), custom recognizers + deny-list, fail-closed, Postgres audit (redacted), model allowlist, `.env.example`, encrypted-volume + Entra docs, synthetic fixtures + tests, CI (gitleaks, SAST, image scan, SBOM) | Draft PR, CI green |
| 2 | Entra SSO + MFA (CA, phishing-resistant admin), per-client virtual keys + rotation, MCP gateway + pre_mcp_call, SIEM export, retention 6y/5y, tamper-evident logs | Tests pass |
| 3 | Hardening: non-root/read-only containers, internal TLS, egress allowlist, VLAN, backups 3-2-1 w/ immutable offsite + restore test, patch cadence, IR runbook (DLP failure), threat model + Marko red-team | Restore + red-team pass |
| 4 | Deploy on Cap's hypervisor behind Cloudflare Tunnel+Access (no inbound ports; admin VPN-only) after Marko CLEAR | Acceptance on target |
| 5 | Evidence pack per Reggie control mapping; quarterly review | Reggie sign-off |

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
9. **Cloudflare egress = redacted only (no BAA):** for any traffic reachable via the tunnel, capture egress during fixture suite; assert no raw synthetic PII appears; model-API legs go direct, not via cloudflared.
10. **Model allowlist:** request to non-allowlisted model rejected.

## 5. Out of scope / guardrails for builders
No deploy, no merge without Marko review, no real credentials, no public exposure, no real data.

## 6. HIPAA-eligible Anthropic configuration
- Backend: Anthropic Claude API directly under Cap's BAA. No Bedrock/Vertex/other vendors. `ANTHROPIC_API_KEY` (Cap's HIPAA org key) from env/vault only.
- Allow only BAA-covered endpoints/features; block at LiteLLM (param filtering / allowed routes) everything else — **verify each against Cap's BAA**: beta headers/features, server-side tools (web search, web fetch, code execution), Files API, Message Batches, prompt-caching variants, computer use.
- Zero-data-retention: enable if part of Cap's agreement — **verify ZDR status**.
- LiteLLM: `telemetry: False`; no third-party success/failure callbacks (Langfuse, Helicone, etc.); logs local Postgres only. Open WebUI: disable external web search, analytics, community sharing, external model connections.
- Acceptance test 11: requests with blocked features/beta headers or non-anthropic models are rejected; config check asserts telemetry off and no external callbacks.
