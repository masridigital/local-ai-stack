#!/usr/bin/env bash
# Quarterly restore test. Restores the audit snapshot into a throwaway directory
# and checks the canary. Never restores onto the live data directory.
set -euo pipefail

env_file="${LOCAL_AI_RESTIC_ENV:-/etc/restic/local-ai.env}"
if [[ ! -f "$env_file" ]]; then
  echo "restic restore test skipped: ${env_file} is absent" >&2
  exit 0
fi

set -a
# shellcheck disable=SC1090
. "$env_file"
set +a

data_root="${LOCAL_AI_DATA_ROOT:-/var/lib/local-ai-stack}"
password_file="${RESTIC_PASSWORD_FILE:-}"

if [[ -z "${RESTIC_REPOSITORY:-}" || -z "$password_file" || ! -e "$password_file" ]]; then
  echo "restic restore test skipped: repository is not configured" >&2
  exit 0
fi

export RESTIC_PASSWORD_FILE="$password_file"
export RESTIC_CACHE_DIR="${RESTIC_CACHE_DIR:-${data_root}/backups/cache}"

parent="${data_root}/backups/restore-test"
install -d -m 0700 "$parent"
workdir="$(mktemp -d "${parent}/XXXXXX")"
cleanup() {
  rm -rf "$workdir"
}
trap cleanup EXIT

case "$workdir" in
  "${data_root}/backups/restore-test"/*) ;;
  *)
    echo "refusing restore target ${workdir}" >&2
    exit 1
    ;;
esac

if ! snapshot_count="$(
  /usr/bin/restic snapshots --tag audit --json | python3 -c 'import json,sys; data=json.load(sys.stdin); print(len(data) if isinstance(data, list) else 0)'
)"; then
  echo "restic restore test failed: cannot read audit snapshots" >&2
  exit 1
fi
if [[ "$snapshot_count" -lt 1 ]]; then
  echo "restic restore test failed: no audit snapshot" >&2
  exit 1
fi

/usr/bin/restic restore latest --tag audit --target "$workdir"

found="$(find "$workdir" -type f -name canary -print -quit)"
if [[ -z "$found" ]]; then
  echo "restic restore test failed: canary file missing" >&2
  exit 1
fi
if ! grep -qx 'local-ai-stack-backup-canary' "$found"; then
  echo "restic restore test failed: canary contents do not match" >&2
  exit 1
fi

echo "restic restore test passed"
