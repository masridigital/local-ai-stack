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
