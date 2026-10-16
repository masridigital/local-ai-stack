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
root.mkdir(parents=True, exist_ok=True)
with (root / "argv.log").open("a", encoding="utf-8") as handle:
    handle.write(" ".join(args) + "\\n")
if command == "backup":
    if os.environ.get("RESTIC_FAIL_BACKUP") == "1":
        sys.exit(1)
    (root / "snap-audit").write_text("1\\n", encoding="utf-8")
    for item in positional[1:]:
        path = Path(item)
        if path.is_file() and path.name == "canary":
            (root / "canary").write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
        if path.is_file() and path.name == "litellm.dump":
            (root / "litellm.dump").write_bytes(path.read_bytes())
            (root / "litellm.mode").write_text(format(path.stat().st_mode & 0o777, "o"), encoding="utf-8")
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
    environment.pop("LOCAL_AI_LUKS_CHECK", None)
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


def _luks_ok(tmp_path: Path) -> str:
    script = tmp_path / "luks-ok"
    script.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    script.chmod(0o755)
    return str(script)


def _root_password(tmp_path: Path) -> Path:
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
    return password_file


def _fake_restic(tmp_path: Path) -> Path:
    fake = tmp_path / "fake-restic"
    fake.write_text(FAKE_RESTIC, encoding="utf-8")
    fake.chmod(0o755)
    return fake


def test_backup_and_restore_round_trip(tmp_path: Path) -> None:
    password_file = _root_password(tmp_path)
    assert stat.S_IMODE(password_file.stat().st_mode) == 0o600

    data = tmp_path / "data"
    (data / "webui").mkdir(parents=True)
    offsite = data / "backups" / "offsite"
    fake = _fake_restic(tmp_path)
    env_file = _write_env(tmp_path, password_file, RESTIC_OFFSITE_REPOSITORY=str(offsite))
    extra = {"RESTIC_BIN": str(fake), "LOCAL_AI_LUKS_CHECK": _luks_ok(tmp_path)}

    backup = _run(BACKUP, env_file, extra)
    assert backup.returncode == 0, backup.stderr
    assert "restic backup complete" in backup.stdout
    assert (data / "backups" / "canary").read_text(encoding="utf-8").strip() == CANARY
    assert (offsite / "config").is_file()
    log = (data / "backups" / "repo" / "argv.log").read_text(encoding="utf-8")
    assert "forget --tag ephi --prune --keep-within 30d" in log
    assert "forget --tag audit --prune --keep-within 6y" in log
    assert "--keep-daily" not in log
    assert "--keep-yearly" not in log

    restore = _run(RESTORE, env_file, extra)
    assert restore.returncode == 0, restore.stderr
    assert "restic restore test passed" in restore.stdout


def test_pg_dump_is_captured_by_root_and_then_deleted(tmp_path: Path) -> None:
    password_file = _root_password(tmp_path)
    data = tmp_path / "data"
    ready = tmp_path / "pg-isready"
    ready.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    ready.chmod(0o755)
    runuser = tmp_path / "runuser"
    runuser.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "if '-f' in sys.argv:\n"
        "    sys.stderr.write('pg_dump cannot open the staging path\\n')\n"
        "    sys.exit(1)\n"
        "if 'postgres' not in sys.argv or '-Fc' not in sys.argv:\n"
        "    sys.stderr.write('unexpected runuser args\\n')\n"
        "    sys.exit(2)\n"
        "sys.stdout.buffer.write(b'PGDMP-synthetic\\n')\n",
        encoding="utf-8",
    )
    runuser.chmod(0o755)
    env_file = _write_env(tmp_path, password_file)
    extra = {
        "RESTIC_BIN": str(_fake_restic(tmp_path)),
        "LOCAL_AI_LUKS_CHECK": _luks_ok(tmp_path),
        "BACKUPS_REQUIRE_POSTGRES": "1",
        "PG_ISREADY_BIN": str(ready),
        "RUNUSER_BIN": str(runuser),
        "PG_DUMP_BIN": "/usr/bin/pg_dump",
    }

    backup = _run(BACKUP, env_file, extra)
    assert backup.returncode == 0, backup.stderr
    dump = data / "backups" / "staging" / "litellm.dump"
    assert not dump.exists()
    staging = data / "backups" / "staging"
    assert stat.S_IMODE(staging.stat().st_mode) == 0o700
    saved = data / "backups" / "repo" / "litellm.dump"
    assert saved.read_bytes() == b"PGDMP-synthetic\n"
    assert (data / "backups" / "repo" / "litellm.mode").read_text(encoding="utf-8") == "600"
    script = BACKUP.read_text(encoding="utf-8")
    dump_lines = [line for line in script.splitlines() if "pg_dump_bin" in line and "-Fc" in line]
    assert len(dump_lines) == 1
    assert "-f" not in dump_lines[0]
    assert ">" in dump_lines[0]


def test_staged_dump_is_deleted_when_backup_fails(tmp_path: Path) -> None:
    password_file = _root_password(tmp_path)
    ready = tmp_path / "pg-isready"
    ready.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    ready.chmod(0o755)
    runuser = tmp_path / "runuser"
    runuser.write_text(
        "#!/bin/sh\nprintf '%s\\n' PGDMP-synthetic\n",
        encoding="utf-8",
    )
    runuser.chmod(0o755)
    env_file = _write_env(tmp_path, password_file)
    extra = {
        "RESTIC_BIN": str(_fake_restic(tmp_path)),
        "LOCAL_AI_LUKS_CHECK": _luks_ok(tmp_path),
        "BACKUPS_REQUIRE_POSTGRES": "1",
        "PG_ISREADY_BIN": str(ready),
        "RUNUSER_BIN": str(runuser),
        "RESTIC_FAIL_BACKUP": "1",
    }

    backup = _run(BACKUP, env_file, extra)
    assert backup.returncode != 0
    assert not (tmp_path / "data" / "backups" / "staging" / "litellm.dump").exists()


def test_unlisted_env_key_is_rejected(tmp_path: Path) -> None:
    env_file = tmp_path / "local-ai.env"
    env_file.write_text(
        f"RESTIC_REPOSITORY={tmp_path / 'repo'}\nUNLISTED_TUNING=synthetic\n",
        encoding="utf-8",
    )
    result = _run(BACKUP, env_file)
    assert result.returncode != 0
    assert "not allow-listed: UNLISTED_TUNING" in result.stderr


def test_stretched_retention_is_rejected(tmp_path: Path) -> None:
    env_file = _write_env(tmp_path, tmp_path / "missing-password", RESTIC_KEEP_WITHIN_AUDIT="12y")
    result = _run(BACKUP, env_file)
    assert result.returncode != 0
    assert "keep-within 6y" in result.stderr

    chat = _write_env(tmp_path, tmp_path / "missing-password", RESTIC_KEEP_WITHIN_EPHI="60d")
    result = _run(BACKUP, chat)
    assert result.returncode != 0
    assert "keep-within 30d" in result.stderr


def test_repository_must_be_on_dm_crypt(tmp_path: Path) -> None:
    password_file = _root_password(tmp_path)
    env_file = _write_env(tmp_path, password_file)
    result = _run(BACKUP, env_file, {"RESTIC_BIN": str(_fake_restic(tmp_path))})
    assert result.returncode != 0
    assert "not on dm-crypt" in result.stderr
    assert not (tmp_path / "data" / "backups" / "repo" / "config").exists()
    assert "/opt/local-ai-stack/scripts/check_luks.py" in (ROOT / "deploy" / "backup" / "restic-env.sh").read_text(encoding="utf-8")


def test_default_alert_route_writes_the_journal(tmp_path: Path) -> None:
    logger = tmp_path / "logger"
    logger.write_text(
        "#!/bin/sh\nprintf '%s\\n' \"${RESTIC_PASSWORD:-unset}\"\nprintf '%s\\n' \"$*\"\n",
        encoding="utf-8",
    )
    logger.chmod(0o755)
    environment = os.environ.copy()
    environment.pop("LOCAL_AI_RESTIC_ALERT_HOOK", None)
    environment.pop("LOCAL_AI_RESTIC_ALERT_ROUTE", None)
    environment["LOGGER_BIN"] = str(logger)
    environment["RESTIC_PASSWORD"] = "synthetic-not-a-password"
    result = subprocess.run(
        ["bash", str(ALERT)],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    assert result.returncode == 0, result.stderr
    assert "unset" in result.stdout
    assert "local-ai-restic" in result.stdout
    assert "restic backup or restore test failed" in result.stdout
    assert "synthetic-not-a-password" not in result.stdout


def test_offhost_alert_mail_is_refused(tmp_path: Path) -> None:
    sendmail = tmp_path / "sendmail"
    sendmail.write_text("#!/bin/sh\nprintf '%s\\n' sent\n", encoding="utf-8")
    sendmail.chmod(0o755)
    environment = os.environ.copy()
    environment["LOCAL_AI_RESTIC_ALERT_ROUTE"] = "mail"
    environment["LOCAL_AI_RESTIC_ALERT_MAIL"] = "ops@example.com"
    environment["SENDMAIL_BIN"] = str(sendmail)
    result = subprocess.run(
        ["bash", str(ALERT)],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    assert result.returncode != 0
    assert "no egress rule" in result.stderr
    assert "sent" not in result.stdout


@pytest.mark.parametrize("recipient", ["root", "root@localhost"])
def test_local_alert_mail_is_delivered_without_the_password(tmp_path: Path, recipient: str) -> None:
    sendmail = tmp_path / "sendmail"
    sendmail.write_text("#!/bin/sh\ncat\n", encoding="utf-8")
    sendmail.chmod(0o755)
    environment = os.environ.copy()
    environment["LOCAL_AI_RESTIC_ALERT_ROUTE"] = "mail"
    environment["LOCAL_AI_RESTIC_ALERT_MAIL"] = recipient
    environment["SENDMAIL_BIN"] = str(sendmail)
    environment["RESTIC_PASSWORD"] = "synthetic-not-a-password"
    result = subprocess.run(
        ["bash", str(ALERT)],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    assert result.returncode == 0, result.stderr
    assert f"To: {recipient}" in result.stdout
    assert "restic backup or restore test failed" in result.stdout
    assert "synthetic-not-a-password" not in result.stdout


def test_unconfigured_alert_hook_fails_loudly() -> None:
    environment = os.environ.copy()
    environment["LOCAL_AI_RESTIC_ALERT_ROUTE"] = "hook"
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
    environment["LOCAL_AI_RESTIC_ALERT_ROUTE"] = "hook"
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
    environment["LOCAL_AI_RESTIC_ALERT_ROUTE"] = "hook"
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
    defaults_text = (role / "defaults" / "main.yml").read_text(encoding="utf-8")
    assert 'backups_password: ""' in defaults_text
    defaults = yaml.safe_load(defaults_text)
    assert set(defaults["backups_extra_env_allow"]) == {
        "RESTIC_COMPRESSION",
        "RESTIC_PACK_SIZE",
        "RESTIC_PROGRESS_FPS",
        "RESTIC_READ_CONCURRENCY",
        "RESTIC_CACHE_DIR",
    }
    assert defaults["backups_keep_within_ephi"] == "30d"
    assert defaults["backups_keep_within_audit"] == "6y"
    assert defaults["backups_alert_route"] == "journal"
    assert "check_luks.py" in text
    assert "difference(backups_extra_env_allow)" in text
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
