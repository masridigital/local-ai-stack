# Incident response (this stack)

Written plan for the Red lane, for the incident-response element in 16 CFR 314.4(h). It is not Cap’s enterprise plan and it is not legal advice. Counsel decides whether a notice goes out, and which statute applies. This repository does not send notices.

Owner and FTC Qualified Individual for this system: Joseph Masri (Cap).

## When it applies

- Presidio fails closed and users see errors. That is the control working. Review the audit row the same business day and restore Presidio. Do not bypass the gateway, and do not point staff at a tool that has no BAA.
- A prompt or tool result that contains PHI reached a party with no BAA. On this stack that includes Cloudflare, a tunnel, a non-allowlisted model, a non-US Azure region, an `azure_ai/` marketplace model, or a log that stored raw text. Grok Bot and other no-BAA assistants are outside this repo and are still in scope for the assessment if someone pasted PHI there.
- `ANTHROPIC_BAA_ENABLED` was on for an API key whose Anthropic organization is not the organization covered by the BAA and ZDR.

While the stack is down, staff stay off PHI tools. There is no emergency route that sends a raw prompt to a vendor. RTO and RPO are 24 hours (`docs/host-hardening.md`).

## Roles

| Role | Who | Duty on this system |
|---|---|---|
| Qualified Individual and owner | Joseph Masri (Cap) | Decides severity, accepts residual risk, owns the FTC notice decision, and keeps the written record for the annual report under 314.4(i) |
| Designated reviewer | Named in the evidence pack (the policy file’s audit reviewer) | Reads fail-closed rows within one business day and samples allow-rows weekly |
| Counsel | Cap’s counsel | Runs the notification decision, including whether the entity is a 23 NYCRR 500 Covered Entity (see 500.19) and whether the FTC Safeguards Rule applies |
| Marko | Security review | Recognizer, route, and allowlist changes before the next deploy |
| Operator | Whoever holds the host | Containment commands below. Does not draft regulatory notices |

## Detect and contain

1. Record the time the event was known to any workforce member. That time is “discovery” for the FTC rule and the start of the HIPAA clocks. It is not, by itself, the NYDFS determination time.
2. Stop the stack: `sudo systemctl stop local-ai-stack.target`. Leave WireGuard up if that is how the host is administered. Do not start `cloudflared`.
3. Preserve redacted evidence only: `audit_event` rows, `journalctl -u presidio-analyzer -u presidio-anonymizer -u litellm -u policy-gateway -u open-webui -u caddy --since <time>`, `ufw status verbose`, and the `config_hash` on the latest `config_change` row. Do not copy a raw prompt into the ticket, a chat, or `/tmp`.
4. If a credential may have left the host, revoke it at the vendor and replace the root-owned file under `/etc/<app>` (mode 0600). Do not write the new secret into the ticket.
5. Outbound is already default-deny. Do not open it to “get logs off the box” onto a new host.

Memory dumps and disk images are a counsel decision. They are not a default step, and a raw disk image is ePHI.

## HIPAA breach assessment (45 CFR 164.402)

Source: [45 CFR 164.402](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-D/section-164.402) and the [HHS Breach Notification Rule summary](https://www.hhs.gov/hipaa/for-professionals/breach-notification/index.html).

An acquisition, access, use, or disclosure of PHI that the Privacy Rule does not permit is presumed to be a breach unless the covered entity or business associate documents a low probability that the PHI was compromised. The assessment uses at least these four factors, taken together:

1. The nature and extent of the PHI, including the types of identifiers and the likelihood of re-identification.
2. The unauthorized person who used the PHI or to whom the disclosure was made.
3. Whether the PHI was actually acquired or viewed.
4. The extent to which the risk has been mitigated (for example, the recipient confirms deletion and has a duty to protect it).

164.402(1) also excludes three narrow cases: a good-faith, in-scope workforce access that is not further used or disclosed impermissibly; an inadvertent disclosure from one authorized person to another authorized person at the same covered entity or business associate that is not further used or disclosed impermissibly; and a disclosure to a person who the covered entity or business associate believes in good faith could not reasonably have retained the information. A redaction miss to a vendor with no BAA is none of those three.

There is no numeric probability cutoff in 164.402. Do not treat “about half” or any other percentage as the test. If the assessment does not demonstrate a low probability of compromise, notice follows Cap’s breach-notification procedure (internal reference SOP-SEC-010) on counsel’s timeline.

The notice clocks are not in 164.402. They are in the same subpart:

- [164.404](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-D/section-164.404): individuals, without unreasonable delay and no later than 60 calendar days after discovery.
- [164.406](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-D/section-164.406): prominent media outlets, if the breach involves more than 500 residents of a state or jurisdiction.
- [164.408](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-D/section-164.408): the Secretary. For 500 or more individuals, without unreasonable delay and no later than 60 days after discovery. For fewer than 500, no later than 60 days after the end of the calendar year.
- [164.410](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-D/section-164.410): a business associate notifies the covered entity without unreasonable delay and no later than 60 days after discovery.

Encryption in transit does not make a disclosure “secured” once a no-BAA recipient can read the prompt. LUKS protects the disk, not a copy that already left.

## NYDFS 72-hour notice (23 NYCRR 500.17(a))

Sources: [23 NYCRR 500 as published by DFS (July 2026 text)](https://www.dfs.ny.gov/system/files/documents/2026/07/NYCRR-part-500-Cybersecurity-Regulation.pdf), [DFS Cybersecurity Resource Center](https://www.dfs.ny.gov/industry_guidance/cybersecurity), and [23 NYCRR 500.17](https://www.law.cornell.edu/regulations/new-york/23-NYCRR-500.17).

This step applies only if counsel determines the affected entity is a Covered Entity and is not operating under an exemption in 500.19. The technical plan does not make that determination.

A cybersecurity event (500.1(d)) is any act or attempt, successful or not, to gain unauthorized access to, disrupt, or misuse an information system or the information on it. A cybersecurity incident (500.1(g)) is a cybersecurity event at the covered entity, its affiliates, or a third-party service provider that:

1. impacts the covered entity and requires notice to any government body, self-regulatory agency, or other supervisory body; or
2. has a reasonable likelihood of materially harming any material part of the normal operations of the covered entity; or
3. results in ransomware inside a material part of the covered entity’s information systems.

500.17(a)(1) requires the covered entity to notify the Superintendent electronically, on the form on the Department’s website, as promptly as possible and in no event later than 72 hours after determining that a cybersecurity incident has occurred. The 72-hour clock runs from that determination, not from the first alert. 500.17(a)(2) requires prompt answers to DFS questions and a continuing update when material facts change.

Decide the 500.1(g) question and record it, including when the answer is that the event is not a cybersecurity incident and no 72-hour notice is due. A Presidio fail-closed with no disclosure is an event to review. It is not automatically an incident.

500.17(c) is a different clock and applies only if an extortion payment was made: notice within 24 hours of the payment, and a written explanation within 30 days. This runbook does not authorize payment.

## FTC 30-day notice (16 CFR 314.4(j))

Sources: [16 CFR 314.4](https://www.ecfr.gov/current/title-16/chapter-I/subchapter-C/part-314/section-314.4) and the FTC’s [Safeguards Rule notification guidance](https://www.ftc.gov/business-guidance/resources/ftc-safeguards-rule-what-your-business-needs-know).

A notification event is the unauthorized acquisition of unencrypted customer information. Information is unencrypted for this purpose if the encryption key was accessed by an unauthorized person. Unauthorized access is presumed to be unauthorized acquisition unless there is reliable evidence that acquisition did not and could not reasonably have occurred. The definition is in [16 CFR 314.2](https://www.ecfr.gov/current/title-16/chapter-I/subchapter-C/part-314/section-314.2).

If the event involves the information of at least 500 consumers, 314.4(j) requires notice to the Commission as soon as possible and no later than 30 days after discovery. Discovery is the first day the event is known to the financial institution, which includes the day it is known to an employee, officer, or agent other than the person committing the breach. Notice is the electronic form on the FTC website and includes the institution’s name and contact, the types of information, the date or date range if known, the number of consumers affected or potentially affected, a general description, and whether a law-enforcement official has requested a delay in public notice. A law-enforcement delay of public disclosure does not erase the notice to the Commission.

Counsel confirms the consumer count and whether the Safeguards Rule applies to the affected entity. The Qualified Individual records the decision in the incident file and includes it in the annual written report under 314.4(i).

## Recover and close

1. Patch or restore from the encrypted backup. Quarterly restore ownership is on the deploy checklist.
2. Run a synthetic prompt (the fixture MRN, not real PHI) and confirm the audit row is masked.
3. Marko reviews any recognizer or allowlist change before the next apply.
4. Write a short timeline: detection, containment, the 164.402 factors, the NYDFS determination, the FTC count, and what changed.
5. Retain that write-up with the other security documentation for six years (45 CFR 164.316(b)(2)). Do not retain the raw prompt in order to meet that duty.

## Assessment worksheet

| Item | Record |
|---|---|
| Discovery time (first workforce knowledge) | |
| What left the boundary, and which identifiers | |
| Who received it, and do they have a BAA or other duty | |
| Acquired or viewed? Evidence | |
| Mitigation (deletion confirmation, key rotation) | |
| 164.402(1) exception claimed? | |
| Low probability of compromise demonstrated? | |
| NYDFS: Covered Entity? 500.1(g) prong met? Determination time | |
| 72-hour notice made, or reason not made | |
| FTC: Safeguards Rule applies? Consumers affected | |
| 30-day notice made, or reason not made | |
| Qualified Individual | Joseph Masri (Cap) |
