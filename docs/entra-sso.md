# Entra SSO

Open WebUI is the only user-facing app. It is reached over VPN or the LAN address bound by Caddy, with TLS. It is not a Cloudflare Access application. Microsoft Entra ID is the identity provider. Tenant `f7812296-5bce-41dc-8102-b1b270e7c4c7`.

Zitadel is an unused fallback and is not configured on this stack.

## App registration

1. Register an app for Open WebUI. Redirect URI: `https://webui.lan.internal/oauth/microsoft/callback` (the real LAN name, not a public hostname). Platform: web. This is a confidential client: PKCE (`S256`, `OAUTH_CODE_CHALLENGE_METHOD`) runs with the client secret. Do not enable public client flows. The secret stays in `/etc/open-webui/microsoft_client_secret`.
2. Supported accounts: this tenant only.
3. API permissions: `openid`, `email`, `profile`. Admin consent. Optional claim: `roles` in the ID token.
4. App roles, value and display name the same: `phi`, `non-phi`, `admin`. Assign `phi` or `non-phi` for model access. Assign `admin` only to the security group `local-ai-admins` (`LOCAL_AI_ADMIN_GROUP` in `deploy/env/open-webui.env`). That group is small and reviewed before deploy and on every membership change. `admin` alone does not grant a model team.
5. Enterprise application: **Assignment required = Yes**. Scope that assignment to one security group, `PHI-users`. Do not assign the whole tenant. People get an account by being added to that group and given an app role. They cannot self-provision.
6. Create a client secret in the vault. `deploy/install.sh` writes it to `/etc/open-webui/microsoft_client_secret` from `MICROSOFT_CLIENT_SECRET` (mode 0600). Do not put it in a unit file or in git.
7. Set `MICROSOFT_CLIENT_ID` and `MICROSOFT_CLIENT_TENANT_ID` in `/etc/open-webui/config.env` before `deploy/install.sh --apply`. Do not set `AZURE_TENANT_ID` on Open WebUI. LiteLLM does not use an Entra client for Azure OpenAI; it uses the API key in `/etc/litellm/azure_api_key`. The committed file keeps the placeholder client id `00000000-0000-0000-0000-000000000000`. Apply and `open-webui-run.sh` both refuse that zero GUID. `OPENID_PROVIDER_URL` is `https://login.microsoftonline.com/f7812296-5bce-41dc-8102-b1b270e7c4c7/v2.0/.well-known/openid-configuration`.

Conditional Access: require MFA for the app. Admins who can change the stack (the `localai` host group, LiteLLM master key holders, and the Entra `admin` app role) use a phishing-resistant method. Sign-in frequency 8 hours, matching `JWT_EXPIRES_IN=8h`.

## Open WebUI access

Local signup only is off (`ENABLE_SIGNUP=false`). That sentence is not “all signup is off”: OAuth signup stays on (`ENABLE_OAUTH_SIGNUP=true`) so a person already in the `PHI-users` group can get a row. The password form is off (`ENABLE_LOGIN_FORM=false`, `ENABLE_PASSWORD_AUTH=false`). Open WebUI refuses every login whose `roles` claim is outside `phi`, `non-phi`, and `admin` (`ENABLE_OAUTH_ROLE_MANAGEMENT=true`, `OAUTH_ALLOWED_ROLES`). Group management copies that same claim (`ENABLE_OAUTH_GROUP_MANAGEMENT=true`, `OAUTH_GROUPS_CLAIM=roles`).

`DEFAULT_USER_ROLE=pending`. Role management overwrites that only when the claim matches. A pending account cannot chat. There is no local login. `ENABLE_LOGIN_FORM=false` and `ENABLE_PASSWORD_AUTH=false` leave the password form off. The bootstrap row exists so the first Entra login is not promoted to admin. It is not a sign-in path.

Tools and Functions are admin-only. `USER_PERMISSIONS_WORKSPACE_TOOLS_ACCESS`, import, export, and sharing are false, so a non-admin has no Tools workspace. Open WebUI 0.12.2 binds the Functions routes to the admin role. `ENABLE_FUNCTIONS=true` leaves that admin path available. The people who hold it are `local-ai-admins`.

Open WebUI promotes the sole user to admin. A bootstrap account is created at startup from `WEBUI_ADMIN_EMAIL=webui-bootstrap@local-ai.internal` and `WEBUI_ADMIN_PASSWORD` (LoadCredential, mode 0600, generated, not in git). The password form is off, and `OAUTH_MERGE_ACCOUNTS_BY_EMAIL=false`, so that account is not a sign-in path and the first Entra login is not an admin. Human admins come from the Entra app role `admin`.

The same `roles` claim is copied into Open WebUI groups (`OAUTH_GROUPS_CLAIM=roles`). Open WebUI 0.12.2 replaces `{{USER_GROUPS}}` in `OPENAI_API_CONFIGS` with the comma-separated group names (`parse_custom_headers` in `backend/open_webui/utils/headers.py`). A comma is left as a comma, so the gateway receives `X-Entra-App-Roles: phi` or `phi,non-phi`. `phi` may call the PHI models. `non-phi` may call Haiku only.

## Gateway credential and LiteLLM

Open WebUI’s `OPENAI_API_KEY` is the gateway client key. It is not a LiteLLM virtual key. LiteLLM listens on `127.0.0.2:4000`. The Open WebUI unit denies that address, and UFW rejects the `openwebui` user to port 4000 on `127.0.0.1` and `127.0.0.2` before the loopback accept.

The policy gateway holds the LiteLLM virtual key. `scripts/scope_virtual_key.py` asks LiteLLM for a key limited to `foundry-gpt`, plus the Claude model names only when `ANTHROPIC_BAA_ENABLED=true`. The key is never `*`. The master key stays on the LiteLLM unit.

## Gateway key rotation

Rotate `/etc/policy-gateway/gateway_client_key` and the copy at `/etc/open-webui/gateway_client_key` whenever `local-ai-admins` gains or loses a member, and whenever someone who could read either file leaves that role. Generate a new value, write both files mode 0600 and root-owned, and restart `policy-gateway.service` and `open-webui.service`. Do not print the new value. The previous key stops working when the gateway restarts. `host/secrets/populate.sh` will not replace a key that is already present, so an admin change is a deliberate rewrite of both files, not a second populate.

## Azure OpenAI credential

LiteLLM authenticates to Azure OpenAI with `AZURE_API_KEY` from `/etc/litellm/azure_api_key` (mode 0600, root-owned, `LoadCredential`). It does not use a client id or client secret, and the egress list has no LiteLLM row for `login.microsoftonline.com`. The key is scoped in Azure to the one OpenAI resource. Open WebUI’s Entra app is a different registration and is the only client that signs in at that host.

LiteLLM teams `phi` and `non-phi` must exist before it honors `x-litellm-team-id`. The gateway still enforces the model list when LiteLLM ignores that header. `enable_jwt_auth` stays off so the virtual key remains the credential.

## Automatic logoff

The Open WebUI JWT expires after 8 hours. VPN access for PHI users should use the same Conditional Access sign-in frequency. There is no Cloudflare Access session for this UI.

## Emergency access

When Entra is down, do not point users at a public fallback and do not paste PHI into a tool that has no BAA. Do not turn `ENABLE_LOGIN_FORM` back on.

`deploy/break-glass-enable.sh` is not an emergency login. It refuses a secret on the command line, checks that `BREAK_GLASS_SECRET_FILE` is mode `0600`, and exits 1. It does not read the secret into the log, does not change Open WebUI, and does not enable the password form. If `BREAK_GLASS_AUDIT_LOG` is set, it appends one line that names the event and omits the secret. Restoring access means restoring Entra.

There is no shared daily admin password in the repo.

## LiteLLM admin API

LiteLLM binds `127.0.0.2:4000` and has no tunnel route. The master key is `/etc/litellm/litellm_master_key`. An admin on the VPN can open a local SSH forward only: `ssh -L 4000:127.0.0.2:4000`. `AllowTcpForwarding local` and `PermitOpen 127.0.0.2:4000` allow that. `PermitTunnel no` and `AllowStreamLocalForwarding no` refuse tun devices and local socket forwarding. Remote TCP forwarding stays closed.
