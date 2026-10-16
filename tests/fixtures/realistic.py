#!/usr/bin/env python3
"""Realistic-format synthetic corpus. Seed 4242. Not real persons."""

from __future__ import annotations

import base64
import json
from pathlib import Path

from faker import Faker

HEADER = "SYNTHETIC — FAKE DATA — NOT REAL PERSONS"
SEED = 4242


def emails() -> list[str]:
    fake = Faker("en_US")
    Faker.seed(SEED)
    return [f"{fake.user_name()}@example.com" for _ in range(4)]


def build() -> dict:
    mail = emails()
    samples = [
        ("PERSON", "Testy McFakerson", "Patient Testy McFakerson arrived for a fictional follow-up."),
        ("PERSON", "Jane Synthetic-Doe", "The encounter note lists Jane Synthetic-Doe as the emergency contact."),
        ("PERSON", "Pat Placeholder", "Pat Placeholder signed the synthetic consent form before leaving."),
        ("PERSON", "Testy McFakerson", "Face sheet names Testy McFakerson as the fictional patient of record."),
        ("DOB", "1900-01-01", "Date of birth 1900-01-01 is implausible on purpose."),
        ("DOB", "1901-02-02", "Alternate DOB 1901-02-02 is recorded on the header."),
        ("DOB", "01/15/1900", "Face sheet lists DOB 01/15/1900 for the drill chart."),
        ("DOB", "02/28/1901", "Birth date 02/28/1901 appears beside the fictional name."),
        ("US_SSN", "000-00-0000", "SSN 000-00-0000 is not a real number."),
        ("US_SSN", "666-12-3456", "SSN 666-12-3456 is rejected by SSA rules."),
        ("US_SSN", "900-00-0001", "SSN 900-00-0001 is in the invalid range."),
        ("US_SSN", "000.00.0000", "Dotted ssn 000.00.0000 uses the same invalid number."),
        ("MRN", "MRN-SYN-0001234", "Chart MRN-SYN-0001234 was created for this test."),
        ("MRN", "MRN-SYN-0009876", "Second chart MRN-SYN-0009876 belongs to the same drill."),
        ("MRN", "MRN:ABC12345", "The labeled chart MRN:ABC12345 was issued by the demo registrar."),
        ("MRN", "MRN-ZYX98765", "Handoff note cites MRN-ZYX98765 as the alternate chart key."),
        ("RECORD_ID", "REC-SYN-000042", "Record REC-SYN-000042 is a fixture."),
        ("RECORD_ID", "REC-SYN-000043", "Record REC-SYN-000043 is a fixture."),
        ("RECORD_ID", "RECORD-SYN12345", "The archive key RECORD-SYN12345 is synthetic."),
        ("RECORD_ID", "RECORD_FAKE999", "Cross-reference RECORD_FAKE999 is not a production id."),
        ("ACCOUNT_ID", "ACCT-SYN-99990000", "Account ACCT-SYN-99990000 is fake."),
        ("ACCOUNT_ID", "ACCT-SYN-99990001", "Account ACCT-SYN-99990001 is fake."),
        ("ACCOUNT_ID", "ACCT-FAKE123456", "Billing account ACCT-FAKE123456 is a drill value."),
        ("ACCOUNT_ID", "ACCT_SYN999900", "Legacy key ACCT_SYN999900 is synthetic."),
        ("NPI", "NPI-SYN-1234567890", "Provider NPI-SYN-1234567890 is prefixed so it cannot be real."),
        ("NPI", "NPI-SYN-1234567891", "Provider NPI-SYN-1234567891 is prefixed so it cannot be real."),
        ("NPI", "NPI:0000000001", "Referring clinician NPI:0000000001 is a reserved placeholder."),
        ("NPI", "NPI-0000000002", "Covering clinician NPI-0000000002 is a reserved placeholder."),
        ("PHONE_NUMBER", "555-0197", "Call 555-0197 which is in the 555-01xx range."),
        ("PHONE_NUMBER", "555-0186", "Call 555-0186 which is in the 555-01xx range."),
        ("PHONE_NUMBER", "555.0104", "After-hours line 555.0104 is fictional."),
        ("PHONE_NUMBER", "555 0122", "Front desk 555 0122 is fictional."),
        ("EMAIL_ADDRESS", mail[0], f"Reach {mail[0]} only."),
        ("EMAIL_ADDRESS", mail[1], f"Copy {mail[1]} only."),
        ("EMAIL_ADDRESS", mail[2], f"Notify {mail[2]} about the drill."),
        ("EMAIL_ADDRESS", mail[3], f"Page {mail[3]} if the queue stalls."),
        ("LOCATION", "123 Fake Street", "Lives at 123 Fake Street, Testville, ZZ 00000."),
        ("LOCATION", "456 Fake Avenue", "Mailing 456 Fake Avenue, Testville, ZZ 00000."),
        ("LOCATION", "789 Demo Road", "Clinic entrance is 789 Demo Road on the campus map."),
        ("LOCATION", "7 Example Boulevard", "The lab drop box is 7 Example Boulevard."),
        ("CREDIT_CARD", "4111 1111 1111 1111", "Card 4111 1111 1111 1111 is the standard test PAN."),
        ("CREDIT_CARD", "4111111111111111", "Card 4111111111111111 is the same PAN without spaces."),
        ("CREDIT_CARD", "4111-1111-1111-1111", "Card 4111-1111-1111-1111 is the same PAN with dashes."),
        ("CREDIT_CARD", "4111 1111 1111 1111", "The sandbox receipt repeats 4111 1111 1111 1111 for the drill."),
    ]
    chart_keys = (
        "PERSON",
        "DOB",
        "US_SSN",
        "MRN",
        "RECORD_ID",
        "ACCOUNT_ID",
        "NPI",
        "PHONE_NUMBER",
        "EMAIL_ADDRESS",
        "LOCATION",
        "CREDIT_CARD",
    )
    chart_rows = []
    for entity in chart_keys:
        chart_rows.append(next(row for row in samples if row[0] == entity))
    plain = "MRN-SYN-0001234"
    token = base64.b64encode(plain.encode("utf-8")).decode("ascii")
    return {
        "header": HEADER,
        "seed": SEED,
        "note": "Clinical prose with realistic identifier shapes. Values are fictional.",
        "samples": [{"entity": entity, "value": value, "text": text} for entity, value, text in samples],
        "chart": " ".join(row[2] for row in chart_rows),
        "chart_values": [{"entity": row[0], "value": row[1]} for row in chart_rows],
        "negative": [
            "ticket #24058",
            "version v1.2.3",
            "IP 192.0.2.10 is TEST-NET-1",
            "the planning window is Q3 2026",
            "build 42 passed the checklist",
            "queue depth is twelve items",
        ],
        "adversarial": [
            {"entity": "MRN", "value": "M R N - S Y N - 0001234", "text": "identifier M R N - S Y N - 0001234 was split"},
            {"entity": "US_SSN", "value": "000.00.0000", "text": "dotted ssn 000.00.0000"},
            {"entity": "PERSON", "value": "Testy McFakerson", "text": '{"patient": "Testy McFakerson"}'},
            {"entity": "MRN", "encoding": "base64", "value": plain, "text": f"attachment {token} end"},
        ],
    }


def main() -> None:
    path = Path(__file__).with_name("realistic_synthetic.json")
    path.write_text(json.dumps(build(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(path)


if __name__ == "__main__":
    main()
