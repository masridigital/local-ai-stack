# SECURITY — local-ai-stack

- **Data:** Red-lane PHI goes only to Anthropic Claude under Cap’s BAA (ZDR included; runtime switch default **off** until the key and org are verified) and to Microsoft-hosted Azure OpenAI in Cap’s tenant (`azure/`, US regions, `gpt-4.1` / `gpt-4o` families). `azure_ai/` is off by default. Abuse-monitoring opt-out is not assumed. No Bedrock or Vertex. No telemetry and no third-party callbacks.
- **Ingress:** Open WebUI and LiteLLM are VPN/LAN only. They are not on Cloudflare Tunnel. Cap declined a Cloudflare BAA. The tunnel unit is disabled and its config sinks to `http_status:404`.
- **DLP:** Presidio `pre_call` and `post_call`, threshold 0.4, `default_on`. Analyzer or anonymizer failure, timeout, 5xx, or malformed JSON blocks the request and the model is not called. Streaming is disabled. Presidio is a seatbelt, not Safe Harbor de-identification. Recall floors and the accepted residual risk are in `docs/residual-risk.md`. A miss toward a no-BAA party is an incident (`docs/incident-response.md`), including NYDFS 72-hour and FTC 30-day notice decisions.
- **Open WebUI:** Chat history, uploads, and the search index are ePHI on the LUKS volume, retained 30 days. Uploads and web search are off. Embeddings are the local sentence-transformers model. Session JWT expires in 8 hours.
- **Identity:** Entra ID SSO and MFA, phishing-resistant for admins. Break-glass is `deploy/break-glass-enable.sh` (secret file, not argv). No shared daily admin account.
- **Network:** Default deny inbound and outbound. Destination list: `deploy/egress-destinations.yaml`. Admin UI is VPN-only. Internal services have no host ports. Docker does not listen on a TCP socket.
- **Secrets:** Docker secrets, mode 0600, root-owned. `.env` is git-ignored. `.env.example` is placeholders. gitleaks runs in CI.
- **Encryption:** LUKS for the VM disk and the Docker data directories. TLS 1.2+ on the LAN proxy. Postgres and Presidio stay on an internal bridge on the same host. Encrypted backups use keys held separately.
- **Supply chain:** Images pinned by tag and digest, including official `mcr.microsoft.com/presidio-*` `2.2.362`. Monthly updates wait for Marko’s review of release notes.
- **Logging:** Metadata and redacted payloads only. User identity is the Entra object id. Config changes are audited. Review cadence: fail-closed within one business day, weekly sample, quarterly access review. Retention: 6 years HIPAA documentation, 5 years NYDFS 500.6. Chat content is not kept that long; see `docs/disposal-schedule.md`.
- **Change control:** Marko security review before any merge or deploy.
- **Reporting:** Report vulnerabilities privately to Joseph Masri. Do not open a public issue.
- **Host:** Ubuntu Server LTS. See `docs/host-hardening.md`.
