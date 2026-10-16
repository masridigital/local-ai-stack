# Residual risk

Cap accepts this residual risk for the Red lane as of 2026-10-16.

Presidio, the custom recognizers, and the synthetic deny-list reduce how often identifiers reach a model. They do not de-identify under HIPAA Safe Harbor §164.514(b). A masked string is still not a basis for sending the underlying PHI to a vendor with no BAA. Red-lane work stays on this stack, on the VPN, and only on the allowlisted Anthropic and Azure OpenAI backends.

## What the gates cover

`litellm/policy.yaml` `recall_floors` are measured on `tests/fixtures/synthetic.json` (header `SYNTHETIC — FAKE DATA — NOT REAL PERSONS`, Faker seed 4242):

| Entity | Minimum recall |
|---|---|
| PERSON (synthetic deny-list) | 1.00 |
| DOB | 1.00 |
| US_SSN | 1.00 |
| MRN | 1.00 |
| RECORD_ID | 1.00 |
| ACCOUNT_ID | 1.00 |
| NPI | 1.00 |
| EMAIL_ADDRESS | 1.00 |
| CREDIT_CARD | 1.00 |
| PHONE_NUMBER | 0.95 |
| LOCATION | 0.90 |

Any score at or above 0.4 is masked. A score is not “detected but allowed through.”

The adversarial fixture set (spaced MRN, dotted SSN, a name inside JSON, base64 of a synthetic MRN) is part of the regression tests. It is not a claim that every obfuscation will be caught.

## What remains

- Clinical prose that never states a name, MRN, or other pattern (“the patient in room 4 who had the transplant”) can pass.
- Names that are not on the deny-list depend on Presidio’s NER model and will be missed some of the time. Production deny-lists of client names come from the vault and are not committed.
- Novel encodings, images, and scanned documents are blocked when the gateway sees non-text parts, and missed when someone pastes a picture’s words in a form we did not test.
- Open WebUI stores the raw prompt on the LUKS volume until the 30-day purge. That copy is ePHI inside Cap’s boundary. It is not redacted.

A miss that leaves Cap’s boundary toward a no-BAA party is an incident. The assessment steps are in `docs/incident-response.md`.

## Who the audit says sent the chat

For this pilot, attribution is asserted by Open WebUI after Entra sign-in. The gateway stores the id and email Open WebUI forwards. It does not yet check an Entra token. Two records back that assertion: the chat-owner row in Open WebUI (the chat’s user id on the LUKS volume) and the Entra sign-in logs for tenant `f7812296-5bce-41dc-8102-b1b270e7c4c7`.

After the pilot, Open WebUI forwards the Entra token, the gateway validates the JWT, and the audit user id is the `oid` claim.

These conditions are required before deploy:

1. nftables and UFW allow TCP/8088 only from the `openwebui` uid.
2. Tools and Functions are admin-only. The admin app role is assigned only to the reviewed group `local-ai-admins`.
3. Sign-in is Entra only. The password form is off. The gateway rejects a missing user id. The audit row stores both email and id.
4. This section is the statement of how attribution works, including the post-pilot JWT plan above.
5. The gateway client key is rotated when `local-ai-admins` membership changes. See `docs/entra-sso.md`.
