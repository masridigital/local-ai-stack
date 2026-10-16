# Host baseline

This directory is the Proxmox guest baseline for an Ubuntu Server LTS VM. The stack is native: pip virtualenvs under `/opt`, systemd units, and no Docker.

`deploy/install.sh --apply` calls these scripts. `deploy/install.sh --check` runs `host/install.sh --check` and the LUKS walker self-check. It does not change the host.

## What apply installs

- `qemu-guest-agent`, with `guest-exec` and guest-file RPCs blocked. Filesystem freeze stays available for Proxmox backups.
- LUKS for `/var/lib/local-ai-stack`. A disk that is already encrypted is left alone. A spare disk is formatted only when `LUKS_DISK` is set and `LUKS_FORMAT_CONFIRM` equals that device path. The passphrase is a hidden prompt or `LUKS_PASSPHRASE`, passed to cryptsetup on stdin, and never echoed.
- CIS-style baseline: pwquality, module denylist, shell timeout, sudo `use_pty` with a logfile, faillock settings (the PAM stack is not rewritten), and a login banner.
- `auditd` rules for identity files, sudoers, crypttab, UFW, sysctl, and the secret directories.
- Unattended-upgrades from security origins only, with reboot at 03:30.
- SSH keys only, no root login, no agent or TCP forwarding. The drop-in sorts first so it wins.
- UFW default deny in and out. Per-destination egress is an owner match on resolved addresses.

## Secrets

`host/secrets/populate.sh` prompts with a hidden read, writes mode 0600 through Python stdin, and refuses to run under xtrace. Existing 0600 files are kept. It generates the Postgres password, the LiteLLM master key, the Open WebUI secret, the bootstrap admin password, and the gateway client key. It does not generate a LiteLLM virtual key and it does not write the Anthropic key. `HOST_SECRET_ROOT` relocates the tree for tests.

The Anthropic key is written by `deploy/install.sh` only when `ANTHROPIC_BAA_ENABLED=true`.
