# Entra SSO

Open WebUI is the only user-facing app. It is reached over VPN or the LAN address bound by Caddy, with TLS. It is not a Cloudflare Access application.

## App registration

1. In Cap’s Entra tenant, register an app for Open WebUI. Redirect URI: `https://webui.lan.internal/oauth/microsoft/callback` (the real LAN name, not a public hostname).
2. Supported accounts: this tenant only.
3. API permissions: `openid`, `email`, `profile`. Admin consent.
4. Create a client secret in the vault. `deploy/install.sh` writes it to `/etc/open-webui/microsoft_client_secret` from `MICROSOFT_CLIENT_SECRET` (mode 0600). Do not put it in a unit file or in git.
5. Set `MICROSOFT_CLIENT_ID`, `AZURE_TENANT_ID`, and `OPENID_PROVIDER_URL` (`https://login.microsoftonline.com/<tenant>/v2.0/.well-known/openid-configuration`) in `/etc/open-webui/config.env`.

Conditional Access: require MFA for the app. Admins who can change the stack (the `localai` host group, LiteLLM master key holders) use a phishing-resistant method. Sign-in frequency 8 hours, matching `JWT_EXPIRES_IN=8h`.

Password login on Open WebUI is off (`ENABLE_LOGIN_FORM=false`). Signup is off.

## Automatic logoff

The Open WebUI JWT expires after 8 hours. VPN access for PHI users should use the same Conditional Access sign-in frequency. There is no Cloudflare Access session for this UI.

## Emergency access

When Entra is down, do not point users at a public fallback and do not paste PHI into a tool that has no BAA.

1. Two people retrieve the break-glass secret from the vault.
2. Store it in a root-owned mode `0600` file. Run `BREAK_GLASS_SECRET_FILE=/path deploy/break-glass-enable.sh` with no arguments.
3. Record the actor in the audit log (`config_change` / break-glass). The script refuses passwords on the command line.
4. Restore Entra, disable the break-glass credential, and rotate it.

There is no shared daily admin password in the repo.

## LiteLLM admin UI

LiteLLM binds `127.0.0.1:4000` and has no tunnel route. The master key is `/etc/litellm/litellm_master_key`. Anyone who needs the admin API uses the VPN and an SSH forward to that loopback port.
