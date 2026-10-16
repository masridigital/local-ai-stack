"""CycloneDX SBOM from images.lock.yaml. No image pull required."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    destination = Path(sys.argv[1] if len(sys.argv) > 1 else "sbom.cdx.json")
    images = yaml.safe_load((ROOT / "images.lock.yaml").read_text(encoding="utf-8"))["images"]
    components = []
    for name, reference in images.items():
        image, digest = reference.split("@", 1)
        components.append(
            {
                "type": "container",
                "name": image,
                "version": digest,
                "purl": f"pkg:oci/{image.split('/')[-1]}@{digest}",
                "properties": [{"name": "local-ai-stack:pin", "value": name}],
            }
        )
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"component": {"type": "application", "name": "local-ai-stack"}},
        "components": components,
    }
    destination.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
