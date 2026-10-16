"""Restic backups stay local, fail closed, and alert when the hook is unset.

Synthetic values only. Nothing in this file is a live credential.
"""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

import pytest
import yaml

from scripts.check_tree import check
from scripts.egress_nft import render_nft

ROOT = Path(__file__).resolve().parents[1]
BACKUP = ROOT / "deploy" / "backup" / "restic-backup.sh"
RESTORE = ROOT / "deploy" / "backup" / "restic-restore-test.sh"
ALERT = ROOT / "deploy" / "backup" / "restic-alert.sh"
SCRIPTS = (BACKUP, RESTORE)
CANARY = "local-ai-stack-backup-canary"

FAKE_RESTIC = """#!/usr/bin/env python3
import os
import sys
from pathlib import Path

args = sys.argv[1:]
repo = os.environ.get("RESTIC_REPOSITORY", "")
positional = []
target = None
index = 0
while index < len(args):
    arg = args[index]
    if arg == "-r" and index + 1 < len(args):
        repo = args[index + 1]
        index += 2
        continue
    if arg == "--repo2" and index + 1 < len(args):
        index += 2
        continue
    if arg == "--target" and index + 1 < len(args):
        target = args[index + 1]
        index += 2
        continue
    if arg.startswith("-"):
        index += 1
        continue
    positional.append(arg)
    index += 1

if not repo:
    sys.stderr.write("repo unset\\n")
    sys.exit(2)
root = Path(repo)
command = positional[0] if positional else ""
if command == "cat" and positional[1:] == ["config"]:
    sys.exit(0 if (root / "config").is_file() else 1)
if command == "init":
    root.mkdir(parents=True, exist_ok=True)
    (root / "config").write_text("synthetic\\n", encoding="utf-8")
    sys.exit(0)
if command == "backup":
    root.mkdir(parents=True, exist_ok=True)
    (root / "snap-audit").write_text("1\\n", encoding="utf-8")
    for item in positional[1:]:
        path = Path(item)
        if path.is_file() and path.name == "canary":
            (root / "canary").write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
    sys.exit(0)
if command == "snapshots":
    if (root / "snap-audit").is_file():
        sys.stdout.write('[{"short_id":"synthetic","tags":["audit"]}]\\n')
    else:
        sys.stdout.write("[]\\n")
    sys.exit(0)
if command == "restore":
    if not target:
        sys.stderr.write("missing target\\n")
        sys.exit(2)
    dest = Path(target)
    dest.mkdir(parents=True, exist_ok=True)
    text = (root / "canary").read_text(encoding="utf-8") if (root / "canary").is_file() else ""
    (dest / "canary").write_text(text, encoding="utf-8")
    sys.exit(0)
if command in {"forget", "copy"}:
    sys.exit(0)
sys.stderr.write("unexpected restic args: %s\\n" % args)
sys.exit(2)
"""


def _run(script: Path, env_file: Path, extra: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["LOCAL_AI_RESTIC_ENV"] = str(env_file)
    environment["BACKUPS_REQUIRE_POSTGRES"] = "0"
    environment.pop("RESTIC_PASSWORD", None)
    environment.pop("RESTIC_PASSWORD_FILE", None)
    environment.pop("RESTIC_PASSWORD_COMMAND", None)
    if extra:
        environment.update(extra)
    return subprocess.run(
        ["bash", str(script)],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )


def _write_env(tmp_path: Path, password_file: Path, **extra: str) -> Path:
    data = tmp_path / "data"
    lines = [
        f"RESTIC_REPOSITORY={data / 'backups' / 'repo'}",
        f"RESTIC_PASSWORD_FILE={password_file}",
        f"LOCAL_AI_DATA_ROOT={data}",
    ]
    lines.extend(f"{key}={value}" for key, value in extra.items())
    env_file = tmp_path / "local-ai.env"
    env_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
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
    password_file.write_text("synthetic-not-a-password", encoding="utf-8")
    password_file.chmod(0o644)
    env_file = _write_env(tmp_path, password_file)

    for script in SCRIPTS:
        result = _run(script, env_file)
        assert result.returncode != 0, script.name
        assert "mode 0600" in result.stderr


def test_restic_password_not_owned_by_root(tmp_path: Path) -> None:
    if os.geteuid() == 0:
        pytest.skip("a file created by root is owned by root")
    password_file = tmp_path / "user-owned-password"
    password_file.write_text("synthetic-not-a-password", encoding="utf-8")
    password_file.chmod(0o600)
    env_file = _write_env(tmp_path, password_file)

    for script in SCRIPTS:
        result = _run(script, env_file)
        assert result.returncode != 0, script.name
        assert "owned by root" in result.stderr


def test_inline_restic_password_is_rejected(tmp_path: Path) -> None:
    env_file = _write_env(tmp_path, tmp_path / "missing-password", RESTIC_PASSWORD="synthetic-not-a-password")

    for script in SCRIPTS:
        result = _run(script, env_file)
        assert result.returncode != 0, script.name
        assert "RESTIC_PASSWORD" in result.stderr


@pytest.mark.parametrize(
    "repository",
    [
        "s3:synthetic-bucket",
        "sftp:backup@example.invalid:/repo",
        "rest:http://backup.example.invalid/repo",
        "b2:synthetic-bucket",
        "rclone:remote:bucket",
        "azure:synthetic-container:/repo",
    ],
)
def test_offhost_repository_is_refused(tmp_path: Path, repository: str) -> None:
    env_file = tmp_path / "local-ai.env"
    env_file.write_text(
        f"RESTIC_REPOSITORY={repository}\nRESTIC_PASSWORD_FILE={tmp_path / 'missing'}\n",
        encoding="utf-8",
    )

    for script in SCRIPTS:
        result = _run(script, env_file)
        assert result.returncode != 0, script.name
        assert "off-host restic has no egress rule" in result.stderr
        assert "owned by root" not in result.stderr


def test_offhost_copy_target_is_refused(tmp_path: Path) -> None:
    env_file = _write_env(
        tmp_path,
        tmp_path / "missing-password",
        RESTIC_OFFSITE_REPOSITORY="s3:synthetic-offsite",
    )

    result = _run(BACKUP, env_file)
    assert result.returncode != 0
    assert "off-host restic has no egress rule" in result.stderr
    assert "RESTIC_OFFSITE_REPOSITORY" in result.stderr


def test_backup_and_restore_round_trip(tmp_path: Path) -> None:
    password_file = tmp_path / "password"
    password_file.write_text("synthetic-not-a-password\n", encoding="utf-8")
    password_file.chmod(0o600)
    chown = subprocess.run(
        ["sudo", "-n", "chown", "root:root", str(password_file)],
        check=False,
        capture_output=True,
        text=True,
    )
    if chown.returncode != 0:
        pytest.skip("sudo -n chown is required to satisfy the root owner check")
    assert stat.S_IMODE(password_file.stat().st_mode) == 0o600

    data = tmp_path / "data"
    offsite = data / "backups" / "offsite"
    fake = tmp_path / "fake-restic"
    fake.write_text(FAKE_RESTIC, encoding="utf-8")
    fake.chmod(0o755)
    env_file = _write_env(tmp_path, password_file, RESTIC_OFFSITE_REPOSITORY=str(offsite))
    extra = {"RESTIC_BIN": str(fake)}

    backup = _run(BACKUP, env_file, extra)
    assert backup.returncode == 0, backup.stderr
    assert "restic backup complete" in backup.stdout
    assert (data / "backups" / "canary").read_text(encoding="utf-8").strip() == CANARY
    assert (offsite / "config").is_file()

    restore = _run(RESTORE, env_file, extra)
    assert restore.returncode == 0, restore.stderr
    assert "restic restore test passed" in restore.stdout


def test_unconfigured_alert_hook_fails_loudly() -> None:
    environment = os.environ.copy()
    environment.pop("LOCAL_AI_RESTIC_ALERT_HOOK", None)
    result = subprocess.run(
        ["bash", str(ALERT)],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    assert result.returncode != 0
    assert "restic alert hook is not configured" in result.stderr


def test_relative_alert_hook_is_rejected(tmp_path: Path) -> None:
    hook = tmp_path / "hook.sh"
    hook.write_text("#!/bin/sh\nprintf '%s\\n' alert-sent\n", encoding="utf-8")
    hook.chmod(0o755)
    environment = os.environ.copy()
    environment["LOCAL_AI_RESTIC_ALERT_HOOK"] = hook.name
    result = subprocess.run(
        ["bash", str(ALERT)],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
        cwd=tmp_path,
    )
    assert result.returncode != 0
    assert "absolute path" in result.stderr


def test_configured_alert_hook_is_executed_without_the_password(tmp_path: Path) -> None:
    hook = tmp_path / "hook.sh"
    hook.write_text(
        "#!/bin/sh\n"
        "test \"$#\" -eq 0\n"
        "printf '%s\\n' \"${RESTIC_PASSWORD:-unset}\"\n"
        "printf '%s\\n' alert-sent\n",
        encoding="utf-8",
    )
    hook.chmod(0o755)
    environment = os.environ.copy()
    environment["LOCAL_AI_RESTIC_ALERT_HOOK"] = str(hook)
    environment["RESTIC_PASSWORD"] = "synthetic-not-a-password"
    environment["RESTIC_PASSWORD_FILE"] = "/etc/restic/password"
    result = subprocess.run(
        ["bash", str(ALERT)],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    assert result.returncode == 0, result.stderr
    assert "unset" in result.stdout
    assert "alert-sent" in result.stdout
    assert "synthetic-not-a-password" not in result.stdout


def test_ansible_enables_timers_only_with_a_password() -> None:
    tasks = yaml.safe_load((ROOT / "ansible" / "roles" / "backups" / "tasks" / "main.yml").read_text(encoding="utf-8"))
    enabled = [
        task
        for task in tasks
        if isinstance(task.get("ansible.builtin.systemd"), dict) and task["ansible.builtin.systemd"].get("enabled") is True
    ]
    assert enabled
    for task in enabled:
        assert "length > 0" in task["when"]
    disabled = [
        task
        for task in tasks
        if isinstance(task.get("ansible.builtin.systemd"), dict) and task["ansible.builtin.systemd"].get("enabled") is False
    ]
    assert disabled
    for task in disabled:
        assert "length == 0" in task["when"]

    role = ROOT / "ansible" / "roles" / "backups"
    text = "\n".join(path.read_text(encoding="utf-8") for path in role.rglob("*") if path.is_file())
    assert "RESTIC_PASSWORD" in text
    assert "RESTIC_PASSWORD_COMMAND" in text
    assert "no_log: true" in text
    assert "ufw" not in text.lower()
    assert "cloudflared" not in text.lower()
    assert "backups_password | trim | length > 0" in text
    env_template = (role / "templates" / "local-ai.env.j2").read_text(encoding="utf-8")
    alert_template = (role / "templates" / "alert.env.j2").read_text(encoding="utf-8")
    assert "RESTIC_PASSWORD=" not in env_template
    assert "RESTIC_PASSWORD_COMMAND=" not in env_template
    assert "backups_password" not in alert_template
    defaults = (role / "defaults" / "main.yml").read_text(encoding="utf-8")
    assert 'backups_password: ""' in defaults
    site = (ROOT / "ansible" / "site.yml").read_text(encoding="utf-8")
    assert "\n    - backups\n" in site


def test_units_fail_closed_and_deny_network() -> None:
    backup = (ROOT / "deploy" / "systemd" / "restic-backup.service").read_text(encoding="utf-8")
    restore = (ROOT / "deploy" / "systemd" / "restic-restore-test.service").read_text(encoding="utf-8")
    failure = (ROOT / "deploy" / "systemd" / "restic-failure.service").read_text(encoding="utf-8")
    for unit in (backup, restore, failure):
        assert "IPAddressDeny=any" in unit
        assert "RestrictAddressFamilies=AF_UNIX" in unit
        assert "IPAddressAllow=" not in unit
    assert "OnFailure=restic-failure.service" in backup
    assert "OnFailure=restic-failure.service" in restore
    assert "OnFailure=" not in failure
    assert "EnvironmentFile=/etc/restic/local-ai.env" in backup
    assert "EnvironmentFile=-/etc/restic/alert.env" in failure
    assert "local-ai.env" not in failure
    assert "CapabilityBoundingSet=\n" in restore
    assert "CAP_SETUID" in backup
    timer = (ROOT / "deploy" / "systemd" / "restic-restore-test.timer").read_text(encoding="utf-8")
    assert "OnCalendar=*-01,04,07,10-01 04:00:00" in timer


def test_nft_skuid_gates_stay_ahead_of_loopback() -> None:
    text = render_nft({})
    loop = text.index('oifname "lo" accept')
    for needle in (
        "tcp dport 8888 meta skuid != openwebui reject",
        "tcp dport 8889 meta skuid != litellm reject",
        "tcp dport 8890 meta skuid root accept",
        "tcp dport 8890 meta skuid _apt accept",
        "tcp dport 8890 reject",
        "tcp dport 8891 meta skuid != policy-gateway reject",
        "ip daddr 127.0.0.1 tcp dport 8088 meta skuid != openwebui reject",
        "ip daddr 127.0.0.2 tcp dport 8088 meta skuid != openwebui reject",
    ):
        assert text.index(needle) < loop
    assert "restic" not in text
    assert check() == []
