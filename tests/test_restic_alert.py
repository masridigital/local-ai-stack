"""The restic failure hook stays failed until an operator configures it."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deploy" / "backup" / "restic-alert.sh"


def _run(hook: str | None = None) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment.pop("LOCAL_AI_RESTIC_ALERT_HOOK", None)
    if hook is not None:
        environment["LOCAL_AI_RESTIC_ALERT_HOOK"] = hook
    return subprocess.run(
        ["bash", str(SCRIPT)],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )


def test_unconfigured_alert_hook_fails_loudly() -> None:
    result = _run()
    assert result.returncode != 0
    assert "restic alert hook is not configured" in result.stderr


def test_configured_alert_hook_is_executed(tmp_path: Path) -> None:
    hook = tmp_path / "hook.sh"
    hook.write_text("#!/bin/sh\nprintf '%s\\n' alert-sent\n", encoding="utf-8")
    hook.chmod(0o755)

    result = _run(str(hook))
    assert result.returncode == 0
    assert "alert-sent" in result.stdout
