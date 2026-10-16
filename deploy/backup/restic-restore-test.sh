#!/usr/bin/env bash
# Quarterly restore test. Restores the audit snapshot into a throwaway directory
# and checks the canary. Never restores onto the live data directory.
set -euo pipefail

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
# shellcheck disable=SC1091
. "${script_dir}/restic-env.sh"
data_root="${LOCAL_AI_DATA_ROOT:-/var/lib/local-ai-stack}"
password_file="${RESTIC_PASSWORD_FILE:-}"

export RESTIC_PASSWORD_FILE="$password_file"
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
  "$RESTIC_BIN" snapshots --tag audit --json | python3 -c 'import json,sys; data=json.load(sys.stdin); print(len(data) if isinstance(data, list) else 0)'
)"; then
  echo "restic restore test failed: cannot read audit snapshots" >&2
  exit 1
fi
if [[ "$snapshot_count" -lt 1 ]]; then
  echo "restic restore test failed: no audit snapshot" >&2
  exit 1
fi

"$RESTIC_BIN" restore latest --tag audit --target "$workdir"

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
