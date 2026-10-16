#!/usr/bin/env bash
# Shared checks for the restic backup and restore-test scripts.
# Source this file. The password lives in a root-only 0600 file, not in git.
# Repository paths must be local and absolute. Off-host restic has no egress rule.
set -euo pipefail

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  echo "source restic-env.sh from the backup or restore-test script" >&2
  exit 1
fi

env_file="${LOCAL_AI_RESTIC_ENV:-/etc/restic/local-ai.env}"
if [[ ! -f "$env_file" ]]; then
  echo "restic password file is missing: ${env_file} is absent" >&2
  exit 1
fi

set -a
# shellcheck disable=SC1090
. "$env_file"
set +a

restic_reject_offhost() {
  local label="$1"
  local repo="$2"
  if [[ -z "$repo" ]]; then
    return 0
  fi
  case "$repo" in
    /*)
      case "$repo" in
        *://*)
          echo "off-host restic has no egress rule: ${label} must be a local absolute path" >&2
          exit 1
          ;;
      esac
      ;;
    *)
      echo "off-host restic has no egress rule: ${label} must be a local absolute path" >&2
      exit 1
      ;;
  esac
}

if [[ -z "${RESTIC_REPOSITORY:-}" ]]; then
  echo "restic repository is not configured" >&2
  exit 1
fi

restic_reject_offhost "RESTIC_REPOSITORY" "${RESTIC_REPOSITORY}"
restic_reject_offhost "RESTIC_OFFSITE_REPOSITORY" "${RESTIC_OFFSITE_REPOSITORY:-}"

if [[ -n "${RESTIC_PASSWORD:-}" || -n "${RESTIC_PASSWORD_COMMAND:-}" ]]; then
  echo "restic password must come from the password file, not RESTIC_PASSWORD or RESTIC_PASSWORD_COMMAND" >&2
  exit 1
fi
unset RESTIC_PASSWORD RESTIC_PASSWORD_COMMAND

data_root="${LOCAL_AI_DATA_ROOT:-/var/lib/local-ai-stack}"
password_file="${RESTIC_PASSWORD_FILE:-}"

if [[ -z "$password_file" || ! -e "$password_file" ]]; then
  echo "restic password file is missing" >&2
  exit 1
fi
if [[ ! -s "$password_file" ]]; then
  echo "restic password file is empty" >&2
  exit 1
fi
password_mode="$(stat -c %a "$password_file")"
if [[ "$password_mode" != "600" ]]; then
  echo "restic password file must be mode 0600" >&2
  exit 1
fi
password_owner="$(stat -c %U "$password_file")"
if [[ "$password_owner" != "root" ]]; then
  echo "restic password file must be owned by root" >&2
  exit 1
fi

if [[ ! -x "${RESTIC_BIN:-/usr/bin/restic}" ]]; then
  echo "restic binary is not executable: ${RESTIC_BIN:-/usr/bin/restic}" >&2
  exit 1
fi

export RESTIC_PASSWORD_FILE="$password_file"
export RESTIC_CACHE_DIR="${RESTIC_CACHE_DIR:-${data_root}/backups/cache}"
export RESTIC_BIN="${RESTIC_BIN:-/usr/bin/restic}"
