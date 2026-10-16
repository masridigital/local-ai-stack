"""CycloneDX SBOM from the hashed requirement locks. No package download."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCKS = (
    "requirements/policy-gateway.txt",
    "requirements/litellm.txt",
    "requirements/open-webui.txt",
    "requirements/presidio-analyzer.txt",
    "requirements/presidio-anonymizer.txt",
    "requirements/spacy-model.txt",
)
PIN = re.compile(r"^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?==([^\\\s]+)")
URL_PIN = re.compile(r"^(en_core_web_lg) @ .+(en_core_web_lg-[0-9.]+)")


def components() -> list[dict]:
    found: dict[str, str] = {}
    for relative in LOCKS:
        for line in (ROOT / relative).read_text(encoding="utf-8").splitlines():
            match = PIN.match(line)
            if match:
                found[match.group(1)] = match.group(2)
                continue
            url_match = URL_PIN.match(line)
            if url_match:
                found[url_match.group(1)] = url_match.group(2).split("-", 1)[-1].rstrip(".")
    rows = []
    for name, version in sorted(found.items()):
        rows.append(
            {
                "type": "library",
                "name": name,
                "version": version,
                "purl": f"pkg:pypi/{name}@{version}",
            }
        )
    return rows


def main() -> None:
    destination = Path(sys.argv[1] if len(sys.argv) > 1 else "sbom.cdx.json")
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"component": {"type": "application", "name": "local-ai-stack"}},
        "components": components(),
    }
    destination.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
