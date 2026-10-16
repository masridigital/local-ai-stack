# Deploy checklist

Do not put PHI on this stack until Marko has cleared the build and every line below is true. The Anthropic switch ships **off**.

1. VM is Ubuntu Server LTS, LUKS is up, `/var/lib/local-ai-stack` is on that volume.
2. `deploy/install.sh --apply` has been run (or `ansible-playbook -i ansible/inventory.ini ansible/site.yml`). `cloudflared` is disabled. `ss` shows no public listen except SSH from the VPN, and Caddy only on `127.0.0.1` or `VPN_BIND_IP`. Presidio, LiteLLM, the gateway, and Postgres are on `127.0.0.1`.
3. UFW default deny incoming and outgoing. Owner rules match `deploy/ufw/owner.rules`. `AZURE_API_HOST` is the real `*.openai.azure.com` hostname in a US region (`eastus2` or `westus3`, or another region listed in `litellm/policy.yaml`).
4. Credential files exist, mode 0600, root-owned, under `/etc/litellm`, `/etc/policy-gateway`, `/etc/open-webui`, and `/etc/postgres`: Postgres password, database URL, audit URL, LiteLLM master key, LiteLLM virtual key, Anthropic key, Azure client secret, Open WebUI secret, Entra client secret. cloudflared credentials exist only if a reviewed non-PHI tunnel is ever turned on.
5. **ZDR check (Cap confirmed the BAA includes ZDR).** Before `ANTHROPIC_BAA_ENABLED=true`, confirm in the Anthropic console that this exact API key and organization are the HIPAA org covered by the BAA and that zero data retention is on for that org. Record the date and the org id in the evidence pack. A key from another org stays blocked.
6. Foundry deployment name is set in `AZURE_OPENAI_DEPLOYMENT`. The deployment is Azure OpenAI, Microsoft-hosted, family `gpt-4.1` or `gpt-4o` (including the mini/nano ids in the policy). It is not an `azure_ai/` marketplace model.
7. Abuse-monitoring / human-review opt-out is unchanged unless Cap already has written approval. Do not flip `FOUNDRY_ABUSE_MONITORING_OPT_OUT` on a guess.
8. Entra app redirect URI matches the LAN hostname. Conditional Access requires MFA. Admin sign-in is phishing-resistant. JWT lifetime is 8 hours.
9. A synthetic prompt (the fixture MRN, not real PHI) is masked in the audit row and the row has no raw identifier.
10. Backup restore has a scheduled owner and a quarterly date. Break-glass secret is in the vault, not on the disk in cleartext beyond the sealed file used during an incident.
