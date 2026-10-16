#!/usr/bin/env bash
# Encrypted local restic backup. The password file is root-only and is not in git.
# Chat snapshots are keep-within 30d. Audit snapshots are keep-within 6y.
# Off-host repository URLs are refused. This service has no egress.
set -euo pipefail

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
# shellcheck disable=SC1091
. "${script_dir}/restic-env.sh"
data_root="${LOCAL_AI_DATA_ROOT:-/var/lib/local-ai-stack}"

dump=""
cleanup_staging() {
  if [[ -n "${dump}" && -f "${dump}" ]]; then
    rm -f "${dump}"
  fi
}
trap cleanup_staging EXIT

install -d -m 0700 "${data_root}/backups" "${data_root}/backups/cache"
canary="${data_root}/backups/canary"
printf '%s\n' "local-ai-stack-backup-canary" >"$canary"
chmod 0644 "$canary"

staging="${data_root}/backups/staging"
if [[ "${BACKUPS_REQUIRE_POSTGRES:-1}" == "1" ]]; then
  pg_isready_bin="${PG_ISREADY_BIN:-/usr/bin/pg_isready}"
  runuser_bin="${RUNUSER_BIN:-/usr/sbin/runuser}"
  pg_dump_bin="${PG_DUMP_BIN:-/usr/bin/pg_dump}"
  if ! "$pg_isready_bin" -h /var/run/postgresql -q; then
    echo "postgres is not accepting local connections" >&2
    exit 1
  fi
  # staging stays mode 0700 under the root-only backups directory. postgres
  # cannot open a file there, so root's shell captures pg_dump on stdout.
  install -d -m 0700 "$staging"
  dump="${staging}/litellm.dump"
  "$runuser_bin" -u postgres -- "$pg_dump_bin" -Fc -d litellm > "$dump"
  chmod 0600 "$dump"
fi

if ! "$RESTIC_BIN" cat config >/dev/null 2>&1; then
  "$RESTIC_BIN" init
fi

audit_paths=("$canary")
if [[ -f "${staging}/litellm.dump" ]]; then
  audit_paths+=("${staging}/litellm.dump")
fi
"$RESTIC_BIN" backup --tag audit --tag local-ai-stack "${audit_paths[@]}"

if [[ -d "${data_root}/webui" ]]; then
  "$RESTIC_BIN" backup --tag ephi --tag local-ai-stack \
    --exclude "${data_root}/webui/hf" \
    --exclude "${data_root}/webui/st" \
    "${data_root}/webui"
  "$RESTIC_BIN" forget --tag ephi --prune \
    --keep-within "${RESTIC_KEEP_WITHIN_EPHI:-30d}"
fi

"$RESTIC_BIN" forget --tag audit --prune \
  --keep-within "${RESTIC_KEEP_WITHIN_AUDIT:-6y}"

if [[ -n "${RESTIC_OFFSITE_REPOSITORY:-}" ]]; then
  if ! "$RESTIC_BIN" -r "$RESTIC_OFFSITE_REPOSITORY" cat config >/dev/null 2>&1; then
    "$RESTIC_BIN" -r "$RESTIC_OFFSITE_REPOSITORY" init
  fi
  "$RESTIC_BIN" copy --repo2 "$RESTIC_OFFSITE_REPOSITORY"
fi

echo "restic backup complete"
