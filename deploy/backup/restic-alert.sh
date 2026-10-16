#!/usr/bin/env bash
# OnFailure hook for restic-backup.service and restic-restore-test.service.
#
# The default route writes one line to the journal:
#   journalctl -t local-ai-restic
# backups_alert_route=mail sends that same line to a local recipient.
# backups_alert_route=hook runs an executable absolute path.
#
# None of the routes receive the restic password. restic-failure.service
# denies every network address, so mail must be local submission and a hook
# cannot dial out. Off-host mail and an off-host page have no egress rule.
set -euo pipefail

unset RESTIC_PASSWORD RESTIC_PASSWORD_COMMAND RESTIC_PASSWORD_FILE

route="${LOCAL_AI_RESTIC_ALERT_ROUTE:-journal}"
case "$route" in
  journal)
    logger_bin="${LOGGER_BIN:-/usr/bin/logger}"
    if [[ ! -x "$logger_bin" ]]; then
      echo "restic alert journal logger is not executable: ${logger_bin}" >&2
      exit 1
    fi
    "$logger_bin" -p user.err -t local-ai-restic "restic backup or restore test failed"
    ;;
  mail)
    recipient="${LOCAL_AI_RESTIC_ALERT_MAIL:-}"
    if [[ ! "$recipient" =~ ^[A-Za-z_][A-Za-z0-9_-]*$ && ! "$recipient" =~ ^[A-Za-z_][A-Za-z0-9_-]*@localhost$ ]]; then
      echo "restic alert mail must be a local recipient; off-host mail has no egress rule: ${recipient}" >&2
      exit 1
    fi
    sendmail_bin="${SENDMAIL_BIN:-/usr/sbin/sendmail}"
    if [[ ! -x "$sendmail_bin" ]]; then
      echo "restic alert mail transport is not executable: ${sendmail_bin}" >&2
      exit 1
    fi
    "$sendmail_bin" -t <<EOF
To: ${recipient}
Subject: restic backup or restore test failed

restic backup or restore test failed
EOF
    ;;
  hook)
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
    exec "$hook"
    ;;
  *)
    echo "restic alert route is not journal, mail, or hook: ${route}" >&2
    exit 1
    ;;
esac
