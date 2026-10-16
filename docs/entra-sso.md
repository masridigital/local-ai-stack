# Entra SSO

Open WebUI is the only user-facing app. It is reached over VPN or the LAN address bound by Caddy, with TLS. It is not a Cloudflare Access application. Microsoft Entra ID is the identity provider. Tenant `f7812296-5bce-41dc-8102-b1b270e7c4c7`.

Zitadel is an unused fallback and is not configured on this stack.

## App registration

1. Register an app for Open WebUI. Redirect URI: `https://webui.lan.internal/oauth/microsoft/callback` (the real LAN name, not a public hostname). Platform: web. Allow public client flows so PKCE (`S256`, `OAUTH_CODE_CHALLENGE_METHOD`) can run. The client secret still lives only in `/etc/open-webui/microsoft_client_secret`.
2. Supported accounts: this tenant only.
3. API permissions: `openid`, `email`, `profile`. Admin consent. Optional claim: `roles` in the ID token.
4. App roles, value and display name the same: `phi`, `non-phi`, `admin`. Assign `phi` or `non-phi` for model access. Assign `admin` only to the operators who administer Open WebUI. `admin` alone does not grant a model team.
5. Enterprise application: **User assignment required** is Yes. Assign one security group, `local-ai-users`. Do not assign the whole tenant. People get an account by being added to that group and given an app role. They cannot self-provision.
6. Create a client secret in the vault. `deploy/install.sh` writes it to `/etc/open-webui/microsoft_client_secret` from `MICROSOFT_CLIENT_SECRET` (mode 0600). Do not put it in a unit file or in git.
7. Set `MICROSOFT_CLIENT_ID` in `/etc/open-webui/config.env`. The committed file keeps a placeholder client id. `OPENID_PROVIDER_URL` is `https://login.microsoftonline.com/f7812296-5bce-41dc-8102-b1b270e7c4c7/v2.0/.well-known/openid-configuration`.

Conditional Access: require MFA for the app. Admins who can change the stack (the `localai` host group, LiteLLM master key holders, and the Entra `admin` app role) use a phishing-resistant method. Sign-in frequency 8 hours, matching `JWT_EXPIRES_IN=8h`.

## Open WebUI access

Local signup is off (`ENABLE_SIGNUP=false`). The password form is off (`ENABLE_LOGIN_FORM=false`). OAuth account creation stays on so a person Entra has already accepted can get a row, and Open WebUI refuses every login whose `roles` claim is outside `phi`, `non-phi`, and `admin`.

`DEFAULT_USER_ROLE=pending`. Role management overwrites that only when the claim matches. A pending account cannot chat.

Open WebUI promotes the sole user to admin. A bootstrap account is created at startup from `WEBUI_ADMIN_EMAIL=webui-bootstrap@local-ai.internal` and `WEBUI_ADMIN_PASSWORD` (LoadCredential, mode 0600, generated, not in git). The password form is off, and `OAUTH_MERGE_ACCOUNTS_BY_EMAIL=false`, so that account is not a sign-in path and the first Entra login is not an admin. Human admins come from the Entra app role `admin`.

The same `roles` claim is copied into Open WebUI groups (`OAUTH_GROUPS_CLAIM=roles`). The gateway reads `X-Entra-App-Roles: {{USER_GROUPS}}`. `phi` may call the PHI models. `non-phi` may call Haiku only.

## Gateway credential and LiteLLM

Open WebUI’s `OPENAI_API_KEY` is the gateway client key. It is not a LiteLLM virtual key. LiteLLM listens on `127.0.0.2:4000`. The Open WebUI unit denies that address, and UFW rejects the `openwebui` user to port 4000 on `127.0.0.1` and `127.0.0.2` before the loopback accept.

The policy gateway holds the LiteLLM virtual key. `scripts/scope_virtual_key.py` asks LiteLLM for a key limited to `foundry-gpt`, plus the Claude model names only when `ANTHROPIC_BAA_ENABLED=true`. The key is never `*`. The master key stays on the LiteLLM unit.

LiteLLM teams `phi` and `non-phi` must exist before it honors `x-litellm-team-id`. The gateway still enforces the model list when LiteLLM ignores that header. `enable_jwt_auth` stays off so the virtual key remains the credential.

## Automatic logoff

The Open WebUI JWT expires after 8 hours. VPN access for PHI users should use the same Conditional Access sign-in frequency. There is no Cloudflare Access session for this UI.

## Emergency access

When Entra is down, do not point users at a public fallback and do not paste PHI into a tool that has no BAA.

1. Two people retrieve the break-glass secret from the vault.
2. Store it in a root-owned mode `0600` file. Run `BREAK_GLASS_SECRET_FILE=/path deploy/break-glass-enable.sh` with no arguments.
3. Record the actor in the audit log (`config_change` / break-glass). The script refuses passwords on the command line.
4. Restore Entra, disable the break-glass credential, and rotate it.

There is no shared daily admin password in the repo.

## LiteLLM admin API

LiteLLM binds `127.0.0.2:4000` and has no tunnel route. The master key is `/etc/litellm/litellm_master_key`. Anyone who needs the admin API uses the VPN and an SSH forward to that loopback address.
