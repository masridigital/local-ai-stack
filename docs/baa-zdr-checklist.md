# BAA and ZDR verification checklist

Do this before `ANTHROPIC_BAA_ENABLED` is set true, and before the first real prompt is sent to Foundry. The runtime switch ships off (`litellm/policy.yaml` `anthropic_baa_enabled: false`, and `ANTHROPIC_BAA_ENABLED` defaults false in `stack/server.py`). PHI waits on `docs/deploy-checklist.md` as well.

Qualified Individual and owner: Joseph Masri (Cap). Counsel confirms the signed agreement. This file is the operator’s record that the live key matches that agreement.

## Anthropic

Cap attested in chat on 2026-10-15 ("BAA has ZDR"). Formal document verification is still pending at Cap's 8 AM review. The public product docs describe two arrangements, and they do not automatically travel together:

- [API and data retention](https://platform.claude.com/docs/en/manage-claude/api-and-data-retention) (zero data retention and HIPAA readiness). ZDR means prompts and responses are not stored at rest after the response, except where the law or misuse-fighting requires it. ZDR is enabled per organization. A new organization under the same account does not inherit it.
- The same page says HIPAA readiness is the arrangement for PHI and that ZDR is not also required for HIPAA readiness in general. It also says the signed BAA is the source of truth for which features are covered, and HIPAA readiness is enforced per organization.
- [Commercial BAA overview](https://support.claude.com/en/articles/8114513-business-associate-agreements-baa-for-commercial-customers). Some covered products are not available while ZDR is on unless Anthropic has authorized that organization. That is why the console check is per key and per org, not a note in the repo.

Treat the 2026-10-15 attestation as the instruction for this deployment: both the BAA and ZDR must be true for the organization that owns the key in `/etc/litellm/anthropic_api_key`. It does not replace the console check in the table, and it is not the formal document verification. Do not enable the switch on “the account has a BAA somewhere.”

| Check | Record |
|---|---|
| Signed BAA is in the evidence pack (not in git) | Date, and whether it is the standard Console BAA or a negotiated one |
| Claude Console organization id for this key | Org id. In Console: Organization selector, then Settings → Privacy (`platform.claude.com/settings/privacy`) |
| HIPAA readiness shows enabled for that org | Yes/no, and the date it was enabled |
| ZDR shows enabled for that same org | Yes/no. If the org is HIPAA-ready but ZDR is off, stop. The 2026-10-15 attestation says this BAA includes ZDR |
| The key file on the VM was minted inside that org | Last four characters of the key only, plus the date checked. Do not copy the key into this checklist |
| Features this stack will call are eligible under both columns of Anthropic’s feature table | Messages API chat completions only. Streaming off. No beta header, web search, web fetch, code execution, computer use, Files, or Batches. Those are rejected in `stack/pipeline.py` and covered by `test_10_and_11_allowlist` |
| Models are the allowlist in `litellm/policy.yaml` | `anthropic/claude-sonnet-4-5`, `anthropic/claude-haiku-4-5`, `anthropic/claude-opus-4-5`. Covered Models that require 30-day retention are not on this list |
| LiteLLM telemetry and message logging are off | `litellm/config.yaml`: `telemetry: false`, `turn_off_message_logging: true`, `store_prompts_in_spend_logs: false`, no third-party callbacks |
| Switch flipped only after the rows above are filled | Set `ANTHROPIC_BAA_ENABLED=true` in `/etc/policy-gateway/config.env` and export it for `deploy/install.sh --apply`. Apply writes `/etc/local-ai-stack/egress.env`, the Anthropic credential drop-in, and `/etc/litellm/anthropic_api_key`. Record the commit or the config hash |

Anthropic on Microsoft Foundry, and Claude Platform on AWS, are not this checklist. Anthropic’s data-retention page says HIPAA readiness is not available on those platforms. This stack’s Foundry path is Azure OpenAI, below.

## Foundry (Azure OpenAI, US regions only)

“Foundry” in this repo means a Microsoft-hosted Azure OpenAI deployment (`azure/`), not an Anthropic model sold through Foundry and not an `azure_ai/` marketplace model.

Microsoft’s data-processing description: for a deployment type labeled Global, prompts and responses may be processed in any geography where the model is deployed; for Data Zone, processing stays inside the data zone (a US resource’s Data Zone is the United States); data at rest stays in the resource geography. Sources: [Data, privacy, and security for Azure Direct Models](https://learn.microsoft.com/en-us/legal/cognitive-services/openai/data-privacy) and [region availability for models sold by Azure](https://learn.microsoft.com/en-us/azure/foundry/foundry-models/concepts/models-sold-directly-by-azure-region-availability).

| Check | Record |
|---|---|
| Resource region is one of `eastus`, `eastus2`, `westus`, `westus2`, `westus3`, `centralus`, `northcentralus`, `southcentralus`, `westcentralus` | Region string. These are `litellm/policy.yaml` `foundry.allowed_regions` |
| Deployment type is Standard (regional) or Data Zone (US) | Not Global. A US resource name does not make a Global deployment US-only |
| API host is `https://<name>.openai.azure.com` and `<name>` does not contain a non-US region token | `AZURE_API_HOST` / `AZURE_API_BASE`. Test `test_foundry_region_and_family` rejects `westeurope` and a non-`openai.azure.com` base |
| Deployment name matches `AZURE_OPENAI_DEPLOYMENT` | Placeholder until Cap sets it. Family is `gpt-4.1`, `gpt-4.1-mini`, `gpt-4.1-nano`, `gpt-4o`, or `gpt-4o-mini` |
| `azure_ai/` stays off | `ALLOW_AZURE_AI_THIRD_PARTY` unset or false. Marketplace models may sit outside Microsoft’s BAA |
| Abuse-monitoring / human-review opt-out | Leave `FOUNDRY_ABUSE_MONITORING_OPT_OUT` false unless a written approval is already in the evidence pack. The gateway does not send that header on a guess |
| Microsoft customer agreement / BAA covers this Azure OpenAI resource | Counsel. This repo does not store the agreement |
| LiteLLM uses the Azure API key, not an Entra client | `/etc/litellm/azure_api_key`, mode 0600. There is no Azure client secret on the LiteLLM unit. Open WebUI’s Entra app is a different registration (`docs/entra-sso.md`) |

## Parties that are not on this path

| Party | Rule |
|---|---|
| Cloudflare | No BAA. Cap declined one. Do not publish Open WebUI, the gateway, or LiteLLM. `cloudflared` is not installed. A future non-PHI sink still has to pass Marko and must not add an ingress hostname for those services |
| StackJack, Composio | Not connected. `mcp.allowed_upstreams` is empty. They would see unredacted source data. No tool id until there is a BAA or a written “no PHI in source” scope, and a Masri↔Cap BAA if PHI would flow |
| Bedrock, Vertex | Rejected. Not backends |

## Sign-off

| Role | Name | Date | What was verified |
|---|---|---|---|
| Qualified Individual and owner | Joseph Masri (Cap) | | BAA includes ZDR for the org id written above |
| Operator | | | Key last-four and org id match the files on the VM |
| Counsel | | | Agreements cover the features this stack calls |
| Marko | | | Switch may be turned on at deploy, not from this pull request |
