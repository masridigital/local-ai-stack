#!/usr/bin/env bash
# OnFailure hook for restic-backup.service and restic-restore-test.service.
#
# This script is the installed placeholder. It does not send an alert.
# Set backups_alert_hook in the backups role to an executable absolute path
# the operator owns, for example /usr/local/sbin/local-ai-restic-page. Until
# that path is set and executable, this script exits 1 so a failed backup
# stays failed in systemd.
#
# The hook runs as root, receives no arguments, and is not given the restic
# password. restic-failure.service denies every network address, so the hook
# must be local (a journal note, a file, or a local mailer). An off-host page
# is not enabled: restic has no egress rule.
set -euo pipefail

hook="${LOCAL_AI_RESTIC_ALERT_HOOK:-}"
if [[ -z "$hook" ]]; then
  echo "restic alert hook is not configured: set backups_alert_hook to an executable" >&2
  exit 1
fi
case "$hook" in
  /*) ;;
  *)
    echo "restic alert hook must be an absolute path: ${hook}" >&2
    exit 1
    ;;
esac
if [[ ! -x "$hook" || -d "$hook" ]]; then
  echo "restic alert hook is not executable: ${hook}" >&2
  exit 1
fi
unset RESTIC_PASSWORD RESTIC_PASSWORD_COMMAND RESTIC_PASSWORD_FILE
exec "$hook"
