# SECURITY — local-ai-stack

- **Data:** Red-lane (PHI/NPI) processing only via BAA-covered model endpoints. Test fixtures are synthetic only; real PHI, client, or Lumina data must never be committed, logged in CI, or used in tests.
- **DLP:** Presidio guardrail pre_call + post_call, `default_on: true`, authoritative. Presidio failure ⇒ request blocked (fail closed). Presidio is a seatbelt, not de-identification.
- **Identity:** Entra ID SSO (OIDC) + MFA via Conditional Access; phishing-resistant MFA for admin. Per-client LiteLLM virtual keys; 90-day rotation.
- **Network:** No public exposure, no inbound ports. Dedicated VLAN. Admin UIs VPN-only. Egress allowlist.
- **Secrets:** env vars / Docker secrets / vault only. `.env` git-ignored; gitleaks in CI.
- **Encryption:** encrypted VM disk/LUKS, encrypted Postgres volume, encrypted backups with separately held keys; TLS in transit.
- **Supply chain:** images pinned by tag+digest (incl. `ghcr.io/data-privacy-stack/presidio-*`); monthly update with Marko reviewing release notes.
- **Logging:** metadata + redacted payloads only; retention 6y (HIPAA docs) / 5y (NYDFS 500.6).
- **Change control:** Marko security review required before any merge or deploy.
- **Reporting:** report vulnerabilities privately to Joseph Masri; do not open public issues.
