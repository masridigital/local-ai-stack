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

restic_env_key_allowed() {
  case "$1" in
    RESTIC_REPOSITORY|RESTIC_PASSWORD_FILE|RESTIC_CACHE_DIR|LOCAL_AI_DATA_ROOT|RESTIC_KEEP_WITHIN_EPHI|RESTIC_KEEP_WITHIN_AUDIT|RESTIC_OFFSITE_REPOSITORY|RESTIC_COMPRESSION|RESTIC_PACK_SIZE|RESTIC_PROGRESS_FPS|RESTIC_READ_CONCURRENCY)
      return 0
      ;;
  esac
  return 1
}

while IFS= read -r line || [[ -n "$line" ]]; do
  case "$line" in
    ''|\#*) continue ;;
  esac
  key="${line%%=*}"
  if [[ "$key" == "$line" || -z "$key" ]]; then
    echo "restic env line is not a KEY=value assignment" >&2
    exit 1
  fi
  if ! restic_env_key_allowed "$key"; then
    echo "restic env key is not allow-listed: ${key}" >&2
    exit 1
  fi
done < "$env_file"

case "${RESTIC_KEEP_WITHIN_EPHI:-30d}" in
  30d) ;;
  *)
    echo "chat backup retention must be keep-within 30d" >&2
    exit 1
    ;;
esac
case "${RESTIC_KEEP_WITHIN_AUDIT:-6y}" in
  6y) ;;
  *)
    echo "audit backup retention must be keep-within 6y" >&2
    exit 1
    ;;
esac

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

restic_require_dmcrypt() {
  local target="$1"
  local label="$2"
  if [[ -z "$target" ]]; then
    return 0
  fi
  if [[ -n "${LOCAL_AI_LUKS_CHECK:-}" ]]; then
    if ! "$LOCAL_AI_LUKS_CHECK" --target "$target"; then
      echo "restic repository is not on dm-crypt: ${label}" >&2
      exit 1
    fi
    return 0
  fi
  if ! python3 /opt/local-ai-stack/scripts/check_luks.py --target "$target"; then
    echo "restic repository is not on dm-crypt: ${label}" >&2
    exit 1
  fi
}

restic_require_dmcrypt "${RESTIC_REPOSITORY}" "RESTIC_REPOSITORY"
restic_require_dmcrypt "${RESTIC_OFFSITE_REPOSITORY:-}" "RESTIC_OFFSITE_REPOSITORY"

if [[ ! -x "${RESTIC_BIN:-/usr/bin/restic}" ]]; then
  echo "restic binary is not executable: ${RESTIC_BIN:-/usr/bin/restic}" >&2
  exit 1
fi

export RESTIC_PASSWORD_FILE="$password_file"
export RESTIC_CACHE_DIR="${RESTIC_CACHE_DIR:-${data_root}/backups/cache}"
export RESTIC_BIN="${RESTIC_BIN:-/usr/bin/restic}"
