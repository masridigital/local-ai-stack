#!/usr/bin/env bash
# OnFailure hook for restic-backup.service and restic-restore-test.service.
#
# This script is the installed placeholder. It does not send an alert.
# Set backups_alert_hook in the backups role (or LOCAL_AI_RESTIC_ALERT_HOOK
# when running the script by hand) to an executable absolute path the
# operator owns, for example /usr/local/sbin/local-ai-restic-page. Until
# that path is set and executable, this script exits 1 so a failed backup
# stays failed in systemd instead of looking successful.
#
# The hook runs as root, receives no arguments, and is not given the
# restic password. It can read the journal for the failed unit.
set -euo pipefail

hook="${LOCAL_AI_RESTIC_ALERT_HOOK:-}"
if [[ -z "$hook" ]]; then
  echo "restic alert hook is not configured: set backups_alert_hook to an executable" >&2
  exit 1
fi
if [[ ! -x "$hook" ]]; then
  echo "restic alert hook is not executable: ${hook}" >&2
  exit 1
fi
exec "$hook"
