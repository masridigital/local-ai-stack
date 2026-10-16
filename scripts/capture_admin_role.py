"""Write deploy evidence that local-ai-admins holds the Entra admin app role.

Inputs are Graph JSON the operator already downloaded. This script does not
read a token and does not copy one into the evidence file.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path

GROUP = "local-ai-admins"
ROLE = "admin"


def assignment_count(assignments: dict, app_roles: list[dict], group: str = GROUP) -> int:
    admin_ids = {item.get("id") for item in app_roles if item.get("value") == ROLE}
    count = 0
    for row in assignments.get("value", []):
        if row.get("principalDisplayName") != group:
            continue
        if row.get("principalType") != "Group":
            continue
        if row.get("appRoleId") in admin_ids:
            count += 1
    return count


def build_evidence(assignments: dict, app_roles: list[dict], group: str = GROUP) -> dict:
    count = assignment_count(assignments, app_roles, group)
    return {
        "group": group,
        "role": ROLE,
        "assigned": count > 0,
        "principal_count": count,
        "captured_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def write_evidence(path: Path, payload: dict) -> None:
    path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--assignments", type=Path, required=True)
    parser.add_argument("--app-roles", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--group", default=GROUP)
    args = parser.parse_args()
    assignments = json.loads(args.assignments.read_text(encoding="utf-8"))
    app_roles = json.loads(args.app_roles.read_text(encoding="utf-8"))
    payload = build_evidence(assignments, app_roles, args.group)
    write_evidence(args.output, payload)
    print("assigned" if payload["assigned"] else "not-assigned")
    if not payload["assigned"]:
        raise SystemExit(1)


if __name__ == "__main__":
    sys.exit(main())
