"""Restic backups fail closed when the password file is not provisioned."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = (
    ROOT / "deploy" / "backup" / "restic-backup.sh",
    ROOT / "deploy" / "backup" / "restic-restore-test.sh",
)


def _run(script: Path, env_file: Path) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["LOCAL_AI_RESTIC_ENV"] = str(env_file)
    environment["BACKUPS_REQUIRE_POSTGRES"] = "0"
    environment.pop("RESTIC_PASSWORD", None)
    environment.pop("RESTIC_PASSWORD_FILE", None)
    return subprocess.run(
        ["bash", str(script)],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )


def _write_env(tmp_path: Path, password_file: Path) -> Path:
    env_file = tmp_path / "local-ai.env"
    env_file.write_text(
        f"RESTIC_REPOSITORY={tmp_path / 'repo'}\n"
        f"RESTIC_PASSWORD_FILE={password_file}\n"
        f"LOCAL_AI_DATA_ROOT={tmp_path / 'data'}\n",
        encoding="utf-8",
    )
    return env_file


def test_missing_restic_password_fails_closed(tmp_path: Path) -> None:
    password_file = tmp_path / "missing-password"
    env_file = _write_env(tmp_path, password_file)

    for script in SCRIPTS:
        result = _run(script, env_file)
        assert result.returncode != 0, script.name
        assert "restic password file is missing" in result.stderr


def test_empty_restic_password_fails_closed(tmp_path: Path) -> None:
    password_file = tmp_path / "empty-password"
    password_file.write_text("", encoding="utf-8")
    env_file = _write_env(tmp_path, password_file)

    for script in SCRIPTS:
        result = _run(script, env_file)
        assert result.returncode != 0, script.name
        assert "restic password file is empty" in result.stderr


def test_loose_restic_password_mode_fails_closed(tmp_path: Path) -> None:
    password_file = tmp_path / "loose-password"
    password_file.write_text("not-the-secret", encoding="utf-8")
    password_file.chmod(0o644)
    env_file = _write_env(tmp_path, password_file)

    for script in SCRIPTS:
        result = _run(script, env_file)
        assert result.returncode != 0, script.name
        assert "mode 0600" in result.stderr
