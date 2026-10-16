# Best-practices compliance

Cap’s requirement (2026-10-15): follow the official Cloudflare and Microsoft MCP guidance, cite it, and map every practice to code and tests. This pull request only changes `docs/`. It does not add a runtime control or a test. A practice Phase 1 already implements is mapped to that code and test. Anything else is an explicit deferral with a reason.

This repository is a native Ubuntu policy gateway in front of LiteLLM. It is not a Cloudflare Worker and it is not an Azure API Management instance. PHI does not cross Cloudflare. The MCP allowlist is empty on purpose.

## Official sources

Cloudflare:

- Remote MCP servers: <https://developers.cloudflare.com/agents/model-context-protocol/guides/remote-mcp-server/>
- Agents SDK authorization and `workers-oauth-provider`: <https://developers.cloudflare.com/agents/model-context-protocol/protocol/authorization/> and <https://developers.cloudflare.com/agents/model-context-protocol/guides/securing-mcp-server/>
- Workers security model: <https://developers.cloudflare.com/workers/reference/security-model/>
- Workers best practices (secrets, Web Crypto): <https://developers.cloudflare.com/workers/best-practices/workers-best-practices/>
- Cloudflare Access: <https://developers.cloudflare.com/cloudflare-one/access-controls/policies/> and <https://developers.cloudflare.com/workers/configuration/cloudflare-access/>
- Cloudflare Tunnel: <https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/>

Microsoft and the MCP specification:

- Secure the Azure MCP Server (Entra ID, APIM as the enforcement point, tool poisoning): <https://learn.microsoft.com/en-us/azure/developer/azure-mcp-server/security>
- Azure API Management as an MCP gateway: <https://learn.microsoft.com/en-us/azure/api-management/mcp-server-overview> and <https://learn.microsoft.com/en-us/azure/api-management/secure-mcp-servers>
- MCP specification security best practices (confused deputy, token passthrough, SSRF, session hijacking), 2025-11-25 revision: <https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices>

Payload-protection practices below are the StackJack-shaped list from the same requirement: per-tool authentication and authorization, least privilege, strict schemas, output sanitization, prompt-injection and tool-poisoning defenses, secrets out of payloads and logs, TLS, rate limits, HMAC audit, and version pinning.

## Cloudflare

| Practice | What the doc requires | This repo | Disposition |
|---|---|---|---|
| Remote MCP is authenticated | The remote-MCP guide starts from an open example and then requires user authentication, Cloudflare Access or an OAuth provider, and scoped tool permissions | No remote MCP server is deployed. `litellm/policy.yaml` `mcp.allowed_upstreams` is `[]` | Deferred. Building a Worker MCP would put a no-BAA network on a path Cap closed. The yellow-lane proxy is the other repository |
| `workers-oauth-provider` OAuth 2.1 | Authorization doc: the Worker is the OAuth provider, issues its own token to the MCP client, and must not log the raw access token. Securing-MCP doc: per-client consent before a third-party OAuth redirect, CSRF, sanitized consent fields, CSP, short-lived state, `__Host-` cookies, HMAC on the approved-client cookie | There is no Worker and no OAuth provider in this tree. Users authenticate to Open WebUI with Entra ID (`docs/entra-sso.md`) | Deferred, same reason. Entra on the VPN UI is the identity control that exists. It is not `workers-oauth-provider` |
| Workers security model | Isolates, cordons, and a seccomp sandbox with no filesystem. The binding API is the capability boundary | The analogous boundary is a non-login system user, `ProtectSystem=strict`, `NoNewPrivileges=yes`, `PrivateTmp=yes`, empty `CapabilityBoundingSet=` (`deploy/systemd/*.service`). `scripts/check_tree.py` fails the tree if those drop | Met for the native host. Not a Worker. Test `test_07_and_09_exposure_and_tunnel` runs `check_tree` |
| Secrets out of source | Workers best practices: `wrangler secret put`, never in source; compare secrets with `crypto.subtle.timingSafeEqual` | Secrets are root-owned mode-0600 files via `LoadCredential` (`deploy/write-secret.sh`). Units and `deploy/env` contain no key material | Met. Test `test_08_secrets_are_files_not_env`. Constant-time compare of an HMAC does not exist here because there is no HMAC token |
| Access in front of a published app | Access checks the request before the application runs. Prefer a short access-token lifetime | Open WebUI is not published. Session lifetime is the Open WebUI JWT, 8 hours, plus Conditional Access | Deferred for Access itself: there is no Cloudflare application. Documented in `docs/entra-sso.md` |
| Tunnel is outbound-only and the hostname is protected | Tunnel removes inbound ports; published names still need Access and a tight ingress | `deploy/cloudflared/config.yml` is a single `http_status:404` rule and names no upstream. `install.sh` disables the unit. Egress to `argotunnel` is not installed while `cloudflared_enabled` is false | Met as “do not publish.” Test `test_07_and_09_exposure_and_tunnel` and `test_egress_default_deny`. A future non-PHI tunnel is a Marko change, not a default |

## Microsoft and the MCP specification

| Practice | What the doc requires | This repo | Disposition |
|---|---|---|---|
| Entra ID for MCP, OAuth 2.1, PKCE, exact redirect URIs | Azure MCP security and the APIM secure-MCP article: validate Entra tokens at the gateway (`validate-azure-ad-token`), do not trust a subscription key as a user id | Chat requests require `X-OpenWebUI-User-Id` (`stack/pipeline.py`). The user signed in with Entra at Open WebUI. This process does not validate a JWT itself | Partial, and the gap is deferred. The gateway trusts the header from Open WebUI on loopback. Validating the Entra JWT inside the gateway is real work in the application, and this lane cannot change code. Until that exists, the bind stays `127.0.0.1` so the header is not accepted from the network |
| APIM as the AI/MCP gateway | Overview and secure-MCP articles: one gateway for authn, authz, rate limit, IP filter, and audit, for both inbound clients and outbound tool calls | The choke point is `stack/server.py` on loopback, not API Management | Deferred. Inserting APIM would be a new host and a new data path. The local gateway is the control this repo tests |
| No token passthrough | MCP security best practices: an MCP server must not accept a token that was not issued to it and forward that token downstream | No MCP server is exposed. LiteLLM uses its own virtual key from `LoadCredential`, not the user’s Entra token | Met by absence of the pattern. Test `test_05_pre_mcp_call` rejects unknown upstreams. Re-check if a tool id is added |
| Confused-deputy consent, CSRF, `__Host-` cookies | Same document, for an MCP proxy that uses a static client id with a third-party authorization server | This gateway is not that proxy | Deferred until an MCP OAuth proxy exists. Do not add dynamic client registration in front of StackJack or Composio without that consent design |
| SSRF on OAuth metadata and tool URLs | Clients must not fetch attacker-supplied OAuth or tool URLs. Egress allowlists are the network control the spec points at | `deploy/egress-destinations.yaml` is default deny, owner-matched. MCP hosts are optional and unset | Met for current egress. Test `test_egress_default_deny` |
| Session hijacking | Bind session identifiers to the authenticated user and do not put them in the URL | UI session is the Entra-backed Open WebUI JWT. The gateway does not mint an MCP session id | Deferred for MCP sessions because there is no MCP listener. UI logoff is the 8-hour JWT |

## Payload protection (StackJack-shaped)

| Practice | This repo | Disposition |
|---|---|---|
| Per-tool authentication and authorization | `handle_mcp` requires a user id, an allowlist entry, and an explicit tool id. `*` is rejected (`stack/pipeline.py`) | Met for the empty allowlist. Test `test_05_pre_mcp_call`. A richer per-tool policy is deferred until the first tool id exists; adding one is a BAA decision (`docs/baa-zdr-checklist.md`) |
| Least privilege | Separate system users, empty capability set, UFW owner matches so only `litellm` can reach Anthropic and only `openwebui` can reach Entra. Presidio, Postgres, the gateway, and Caddy are rejected off-loopback | Met. `deploy/ufw/owner.rules`, test `test_egress_default_deny` |
| Strict schemas, reject unknown fields | Chat bodies may contain only `model`, `messages`, `max_tokens`, `temperature`, `top_p`, `stop`, `user`, and `stream` (and `stream: true` is then rejected). `unexpected_params` returns anything else (`stack/policy.py`) | Met. `test_10_and_11_allowlist` covers blocked tools and beta headers. Unknown-parameter rejection is the `param_not_allowlisted` path in `handle_chat` |
| Output sanitization | Presidio masks the model response before it is returned and before it is audited (`handle_chat` post-call, `handle_mcp` on results) | Met for identifiers. Test `test_02_post_call_redaction` |
| Strip instructions from tool results | Not implemented. Masking removes recognizer hits. It does not remove imperative sentences | Deferred. No live tool returns results. A heuristic stripper without a fixture would be a false control. When a tool is added, treat its result as data, keep the allowlist, and add a regression that a planted instruction cannot add a tool or a route. That test belongs in the lane that adds the tool |
| Prompt injection and tool poisoning | Tool definitions are not loaded from upstream. `allowed_upstreams` is empty, so there is no description to pin. Blocked tool types are a fixed set in `litellm/policy.yaml` | Deferred for hash-pinning of descriptions: there is no description. The pin, and a test that a changed description hash is rejected, are required in the same change that adds a tool. Microsoft’s guidance is to re-approve metadata rather than accept a silent change: <https://learn.microsoft.com/en-us/azure/developer/azure-mcp-server/security> |
| Secrets never in payloads or logs | Audit columns are redacted (`postgres/init/001-audit.sql`, `stack/audit.py`). `Handler.log_message` is a no-op. Journald is size-capped. LiteLLM log level is ERROR | Met. Tests `test_06_audit_has_user_and_no_raw_phi` and `test_08_secrets_are_files_not_env` |
| TLS | Caddy TLS 1.2 and 1.3 to the browser. Vendor calls are HTTPS (`api.anthropic.com`, `*.openai.azure.com`). Units on the same VM talk HTTP on `127.0.0.1` | Met for traffic that leaves the host. Loopback HTTP is an accepted residual in `docs/risk-assessment-template.md` (decision 5). Moving those hops to TLS is a host change, not a docs change |
| Rate limits | The APIM and MCP documents both treat rate limits as a gateway control. `stack/server.py` does not limit requests per user | Deferred. This lane cannot add the limiter or a test for it. The host is single-tenant and not on the internet, which reduces exposure and does not replace the control. Add a per-user limit in the gateway before the service is offered to more than Cap’s named users |
| HMAC audit | `config_hash` is SHA-256 of `policy.yaml` at process start (`stack/pipeline.py` `record_config_change`). Rows are not chained or signed | Deferred to Phase 2 tamper-evident logs. Calling the policy hash an HMAC would be wrong. `PLAN.md` already places tamper-evident logging in Phase 2 |
| Version and hash pinning | `requirements/*.txt` ship `--hash=sha256`. `install.sh` installs with `pip --require-hashes`. spaCy is `en_core_web_lg==3.8.0`. Presidio is `2.2.362`. LiteLLM is `1.105.1` | Met. `scripts/check_tree.py`, executed by `test_install_check_twice` and `test_07_and_09_exposure_and_tunnel`. No container digest, because there is no container. CI also runs Trivy filesystem scan and gitleaks (`.github/workflows/ci.yml`) |

## Deferral list (this pull request)

Nothing in this pull request is “fixed in code” or “a test added.” The gaps are:

1. Cloudflare remote MCP, `workers-oauth-provider`, and Access in front of this UI. Reason: Cap declined a Cloudflare BAA, and the PHI path is VPN-only.
2. Entra JWT validation inside the gateway, instead of a loopback user-id header. Reason: application change, outside `docs/`.
3. Azure API Management as the gateway. Reason: this stack’s choke point is the local policy gateway.
4. MCP confused-deputy consent, MCP session binding, instruction-stripping, and pinned tool-description hashes. Reason: no MCP tool is configured. The change that adds a tool owns those controls and their tests.
5. Per-user rate limits. Reason: not implemented; docs-only lane.
6. HMAC-chained audit rows. Reason: Phase 2, already sequenced in `PLAN.md`.
7. TLS on loopback hops. Reason: accepted residual while every hop stays on one VM.
