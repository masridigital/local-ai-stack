#!/usr/bin/env python3
"""Write tests/fixtures/synthetic.json. Seed 4242. Synthetic data only."""

from __future__ import annotations

import json
from pathlib import Path

from faker import Faker

HEADER = "SYNTHETIC — FAKE DATA — NOT REAL PERSONS"
SEED = 4242


def main() -> None:
    fake = Faker("en_US")
    Faker.seed(SEED)
    emails = [f"{fake.user_name()}@example.com" for _ in range(4)]
    phones = [f"555-01{fake.random_int(0, 99):02d}" for _ in range(4)]
    payload = {
        "header": HEADER,
        "seed": SEED,
        "canonical": [
            {"entity": "PERSON", "text": "Patient Testy McFakerson arrived for a fictional visit."},
            {"entity": "PERSON", "text": "Spoke with Jane Synthetic-Doe about a paperwork drill."},
            {"entity": "PERSON", "text": "Pat Placeholder signed the synthetic form."},
            {"entity": "DOB", "text": "Date of birth 1900-01-01 is implausible on purpose."},
            {"entity": "DOB", "text": "Alternate DOB 1901-02-02 used in the fixture."},
            {"entity": "US_SSN", "text": "SSN 000-00-0000 is not a real number."},
            {"entity": "US_SSN", "text": "SSN 666-12-3456 is rejected by SSA rules."},
            {"entity": "US_SSN", "text": "SSN 900-00-0001 is in the invalid range."},
            {"entity": "MRN", "text": "Chart MRN-SYN-0001234 was created for this test."},
            {"entity": "MRN", "text": "Second chart MRN-SYN-0009876."},
            {"entity": "RECORD_ID", "text": "Record REC-SYN-000042 is a fixture."},
            {"entity": "RECORD_ID", "text": "Record REC-SYN-000043 is a fixture."},
            {"entity": "ACCOUNT_ID", "text": "Account ACCT-SYN-99990000 is fake."},
            {"entity": "ACCOUNT_ID", "text": "Account ACCT-SYN-99990001 is fake."},
            {"entity": "NPI", "text": "Provider NPI-SYN-1234567890 is prefixed so it cannot be real."},
            {"entity": "NPI", "text": "Provider NPI-SYN-1234567891 is prefixed so it cannot be real."},
            {"entity": "EMAIL_ADDRESS", "text": f"Reach {emails[0]} only."},
            {"entity": "EMAIL_ADDRESS", "text": f"Copy {emails[1]} only."},
            {"entity": "PHONE_NUMBER", "text": f"Call {phones[0]} which is in the 555-01xx range."},
            {"entity": "PHONE_NUMBER", "text": f"Call {phones[1]} which is in the 555-01xx range."},
            {"entity": "LOCATION", "text": "Lives at 123 Fake Street, Testville, ZZ 00000."},
            {"entity": "LOCATION", "text": "Mailing 456 Fake Avenue, Testville, ZZ 00000."},
            {"entity": "CREDIT_CARD", "text": "Card 4111 1111 1111 1111 is the standard test PAN."},
            {"entity": "CREDIT_CARD", "text": "Card 4111111111111111 is the same PAN without spaces."},
        ],
        "negative": [
            "ticket #24058",
            "version v1.2.3",
            "IP 192.0.2.10 is TEST-NET-1",
            "the planning window is Q3 2026",
        ],
        "adversarial": [
            {"entity": "MRN", "text": "identifier M R N - S Y N - 0001234 was split"},
            {"entity": "US_SSN", "text": "dotted ssn 000.00.0000"},
            {"entity": "PERSON", "text": '{"patient": "Testy McFakerson"}'},
            {"entity": "MRN", "encoding": "base64", "plain": "MRN-SYN-0001234"},
        ],
        "prompt": (
            "Review the fictional chart for Testy McFakerson, DOB 1900-01-01, "
            "SSN 000-00-0000, MRN MRN-SYN-0001234, record REC-SYN-000042, "
            "account ACCT-SYN-99990000."
        ),
    }
    path = Path(__file__).with_name("synthetic.json")
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(path)


if __name__ == "__main__":
    main()
