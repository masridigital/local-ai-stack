# local-ai-stack — PLAN

Task: `local-ai-dlp` · Red lane · Status: Ready. Cap allows this repo to be merged. Do not deploy from this PR.

## 0. Decisions (Cap and Marko, 2026-10-16)

- **Ingress.** Open WebUI and LiteLLM are **VPN/LAN only**. They are never placed on a Cloudflare Tunnel. Cap declined a Cloudflare BAA, so the earlier “CF BAA or VPN” choice is closed: PHI users do not cross Cloudflare. A tunnel file exists only as a sink (`http_status:404`) for a future non-PHI path and is disabled. No ingress rule may target Open WebUI, the policy gateway, or LiteLLM. Test 9 covers that UI leg.
- **Enforcement.** A policy gateway in front of LiteLLM is the tested choke point. LiteLLM `v1.105.1` is pinned and still runs Presidio with `pii_entities_config` (that is what makes invalid analyzer responses fail closed in this version). Streaming is **off**. Untested routes are rejected.
- **Anthropic.** Direct Claude API under Cap’s BAA. Cap confirms the BAA **includes zero data retention**. The runtime switch `ANTHROPIC_BAA_ENABLED` **defaults off** until the deploy checklist verifies that the configured API key and org are the ZDR org. Beta headers, server-side tools (web search, web fetch, code execution, computer use), Files, and Batches are rejected.
- **Foundry.** Default is Azure OpenAI only (`azure/`), Microsoft-hosted, US regions (the allowlist includes `eastus2` and `westus3`), first-party `gpt-4.1` and `gpt-4o` families. Deployment names stay env placeholders. `azure_ai/` marketplace models are **disabled**; they may fall outside Microsoft’s BAA. Abuse-monitoring opt-out is **not assumed**; turn it on only with written approval that already exists.
- **Native install (Cap, 2026-10-15).** No Docker. Open WebUI, LiteLLM, Presidio analyzer, Presidio anonymizer, and the policy gateway are each a hashed virtualenv under `/opt/<app>`, a non-login system user, and a systemd unit (`ProtectSystem=strict`, `NoNewPrivileges=yes`, `PrivateTmp=yes`, empty `CapabilityBoundingSet=`). Caddy binds `127.0.0.1` unless `VPN_BIND_IP` is set. cloudflared and WireGuard come from apt. The spaCy model is pinned at `en_core_web_lg==3.8.0`.
- **Presidio package.** `presidio-analyzer==2.2.362` and `presidio-anonymizer==2.2.362` from PyPI, with hashes. That is the Microsoft release previously shipped as `mcr.microsoft.com/presidio-*:2.2.362`. Newer tags that exist only on `ghcr.io/data-privacy-stack` are not used. The HTTP servers are the 2.2.362 app modules, vendored so they bind loopback.
- **Secrets and ports.** Root-only files under `/etc/<app>/` (mode 0600), loaded with systemd `LoadCredential`. Nothing listens on a wildcard address. Caddy is the only service that may leave loopback, and only onto `VPN_BIND_IP`. Postgres, Presidio, LiteLLM, and the gateway bind `127.0.0.1`.
- **Open WebUI storage.** The data directory (chat history, uploads, search index) is ePHI on the LUKS volume. Uploads, web search, and external embeddings are off. Embeddings stay on the local sentence-transformers model. Chat retention is 30 days.
- **Residual risk.** Presidio is a seatbelt, not Safe Harbor de-identification. Recall floors in `litellm/policy.yaml` are gates on the synthetic corpus. Cap accepts the residual risk that free-text clinical context and novel obfuscation can be missed. A miss that sends PHI to a no-BAA party is an incident: see `docs/incident-response.md`.
- **No Bedrock or Vertex.** Those paths in the older narrative plan are not backends here.

## 1. Architecture

```
User (Entra ID SSO + MFA, VPN/LAN, TLS 1.2+)
  └─► Caddy (apt, 127.0.0.1 or VPN_BIND_IP:443)
        └─► Open WebUI (venv, 127.0.0.1:8080, history on LUKS, uploads off)
              └─► policy gateway (venv, 127.0.0.1:8088, fail closed)
                    ├─► Presidio analyzer 127.0.0.1:3000 and anonymizer 127.0.0.1:3001
                    ├─► Postgres (apt, 127.0.0.1, redacted audit)
                    └─► LiteLLM v1.105.1 (venv, 127.0.0.1:4000)
                          ├─► api.anthropic.com (only if ANTHROPIC_BAA_ENABLED=true)
                          └─► *.openai.azure.com US (azure/ first-party only)
```

Cloudflare Tunnel is not in this path. Egress is default deny; the written list is `deploy/egress-destinations.yaml`.

## 2. Repo layout (Phase 1)

- `deploy/services.yaml` — venv paths, users, ports, credential file names. `deploy/install.sh` and `ansible/` both follow it.
- `requirements/*.txt` — pip locks with `--hash`. `requirements/spacy-model.txt` pins `en_core_web_lg==3.8.0`.
- `litellm/config.yaml` — model list, Presidio `pre_call` + `post_call` + `pre_mcp_call`, `default_on`, telemetry off, no third-party callbacks, message logging off.
- `litellm/policy.yaml` — BAA switch, routes, Foundry region and family allowlist, recall floors.
- `presidio/recognizers/*.yaml` — MRN, RECORD_ID, ACCOUNT_ID, NPI, and the synthetic deny-list. `presidio/server/` is the vendored 2.2.362 HTTP app, bound to loopback.
- `.env.example` — placeholders only, for the operator’s shell when running `install.sh`. systemd does not load it.
- `docs/encrypted-volumes.md`, `docs/entra-sso.md`, `docs/host-hardening.md`, `docs/incident-response.md`, `docs/residual-risk.md`, `docs/deploy-checklist.md`, `docs/disposal-schedule.md`.
- `deploy/systemd/`, `deploy/install.sh`, `ansible/`, `deploy/ufw/`, `deploy/cloudflared/`, `deploy/wireguard/`.
- `tests/` — synthetic fixtures and acceptance tests 1–11.

## 3. Phases

| Phase | Scope | Exit |
|---|---|---|
| 1 | This repo: native venvs, gateway, Presidio, Postgres audit, allowlists, systemd, Ansible, docs, synthetic tests, CI | Ready PR, CI green |
| 2 | Virtual-key rotation, MCP gateway limited to explicit StackJack and Composio tools, SIEM export, tamper-evident logs | Tests pass |
| 3 | Restore test, red-team, remaining recognizer coverage for the HIPAA 18 identifiers | Marko |
| 4 | Deploy on Cap’s hypervisor only after Marko CLEAR. VPN/LAN for this stack. Tunnel stays off unless a reviewed non-PHI route exists | Acceptance on target |
| 5 | Evidence pack and quarterly review | Reggie sign-off |

## 4. Acceptance tests (synthetic data ONLY)

Fixtures in `tests/fixtures/` are labeled `SYNTHETIC — FAKE DATA — NOT REAL PERSONS` (Faker seed 4242). **No real PHI, client data, or Lumina data.**

1. **pre_call redaction** on Anthropic, `azure/`, and (when the test harness enables it) `azure_ai/`.
2. **post_call redaction** on each of those backends.
3. **Custom recognizers** at the score threshold 0.4, with recall floors in `policy.yaml`. Negatives are not masked.
4. **Fail closed** for analyzer down, anonymizer down, timeout, HTTP 5xx, and malformed JSON, on the enabled chat route. Streaming and every other route are rejected. The mock model is not called when Presidio is unavailable.
5. **pre_mcp_call** masks synthetic PHI before a mock MCP server. Default allowlist is empty.
6. **Audit** row per request, with user id, and no raw fixture PHI. Config-change rows are recorded. Journald is size-capped. LiteLLM log level is ERROR. Open WebUI audit level is METADATA.
7. **Exposure:** no wildcard bind. Caddy listens on `127.0.0.1` or `VPN_BIND_IP`. Every other service listens on `127.0.0.1`.
8. **Secrets:** gitleaks plus a check that credentials are `LoadCredential` files (mode 0600), not values in unit files or `deploy/env`.
8b. Tests 1, 2, and 4 each run on mock Anthropic and mock Foundry (`azure/` and `azure_ai/`). Default config still rejects `azure_ai/`.
9. **Cloudflare:** tunnel config has no route to Open WebUI or LiteLLM. Model hosts are direct. UI traffic is not a tunnel hostname.
10. **Model allowlist** rejects unknown models, Bedrock, and Vertex.
11. Beta headers, blocked tools, Files/Batches routes, telemetry, and third-party callbacks fail the config and request checks. BAA switch default off blocks Anthropic before the mock model.

Recall floors (canonical synthetic set): PERSON, DOB, US_SSN, MRN, RECORD_ID, ACCOUNT_ID, NPI, EMAIL, CREDIT_CARD at 1.0; PHONE at 0.95; LOCATION at 0.90. Scores at or above 0.4 are masked. There is no band that is detected and then passed through.

## 5. Out of scope

No deploy from this PR, no real credentials, no public exposure, no real data. Cap allows the merge. Yellow-lane MCP (the other repo) is not built here. StackJack and Composio are named only as the future MCP allowlist kinds; no wildcard tools.

## 6. Anthropic configuration

- `ANTHROPIC_API_KEY` from `/etc/litellm/anthropic_api_key` (mode 0600, `LoadCredential`).
- Allowed models are listed in `litellm/policy.yaml`. Anything else is rejected.
- Allowed parameters: `model`, `messages`, `max_tokens`, `temperature`, `top_p`, `stop`, `user`. `stream: true` is rejected.
- ZDR is in the BAA (Cap, 2026-10-16). Deploy checklist item: confirm the live key and org before the switch is turned on.

## 7. Foundry

- Provider `azure/` only, until `ALLOW_AZURE_AI_THIRD_PARTY` is explicitly set. It defaults false.
- Auth: Entra (`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, and `AZURE_CLIENT_SECRET` in `/etc/litellm/azure_client_secret`). No key in the repo.
- Region from `AZURE_OPENAI_REGION` must be in the US list. API base must be `*.openai.azure.com` and must not name a non-US region.
- Model family from `AZURE_OPENAI_MODEL_FAMILY` must be `gpt-4.1`, `gpt-4.1-mini`, `gpt-4.1-nano`, `gpt-4o`, or `gpt-4o-mini`.
- Deployment name is `AZURE_OPENAI_DEPLOYMENT` (placeholder).
- Abuse-monitoring retention opt-out is optional and only if already approved. The gateway does not send that header.

## Target host

Ubuntu Server LTS. `deploy/install.sh` is idempotent (`--check` in CI, `--apply` on the VM) and `ansible/site.yml` repeats those steps. Units are native systemd, not container orchestration. cloudflared is installed from apt and left disabled. WireGuard is installed from apt and is not started unless `/etc/wireguard/wg0.conf` already exists. Hardening, LUKS, UFW default-deny inbound and outbound, per-user egress, unattended-upgrades, and backups are documented in `docs/host-hardening.md` and `docs/encrypted-volumes.md`.

## Audit review

Fail-closed events are reviewed within one business day. A designated reviewer samples the redacted audit weekly. Access review is quarterly. Rows include the Entra object id (`user_id`) and `config_change` events include that actor and a hash of `policy.yaml`.
