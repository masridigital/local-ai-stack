# Incident response (DLP and breach assessment)

This is the Phase 1 runbook for a DLP failure. It is not a substitute for Cap’s enterprise IR plan or counsel.

## When it applies

- Presidio fails closed (users see errors). That is the control working. Review the audit row the same business day and restore Presidio. Do not bypass the gateway.
- A prompt or tool result with PHI reached a party that has no BAA. For this stack that includes Cloudflare, a tunnel, a non-allowlisted model, or a log that stored raw text. Grok Bot and other no-BAA assistants are out of this repo and are still in scope for the assessment if someone pasted PHI there.
- The Anthropic switch was on for a key whose org is not the ZDR org.

While the stack is down, staff stay in the green lane (no PHI). There is no emergency route that sends raw prompts to a vendor.

## HIPAA breach assessment (45 CFR 164.402)

Treat a redaction miss to a no-BAA party as a security incident and run the four-factor assessment:

1. What PHI was involved, and how identifiable is it?
2. Who received it, and do they have an obligation to protect it?
3. Was the PHI actually acquired or viewed?
4. To what extent has the risk been mitigated (for example, the recipient confirmed deletion)?

Document the answers. If the assessment does not show a low probability that the PHI was compromised, follow Cap’s breach-notification SOP (the internal reference is SOP-SEC-010) and counsel’s timeline. Notification to individuals and HHS is a counsel decision; this repo does not send those notices.

## NYDFS

If the affected entity is a 23 NYCRR 500 Covered Entity, decide within the **72-hour** window of 500.17 whether the event is a cybersecurity event that requires notice to the Department of Financial Services. Record the decision even when the answer is no.

## FTC Safeguards

If the event involves customer information of **500 or more consumers**, the Qualified Individual’s report includes the **30-day** FTC notice under 16 CFR 314.4(j). Counsel confirms the count and whether the rule applies.

## Afterward

- Preserve the redacted audit rows and the config hash. Do not copy raw prompts into the ticket.
- Rotate any key that may have been exposed.
- Marko reviews whether the recognizer or the route allowlist needs a change before the next deploy.
