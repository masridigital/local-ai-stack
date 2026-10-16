#!/usr/bin/env bash
# Encrypted local restic backup. The password file is root-only and is not in git.
# ePHI snapshots are kept 30 days. Audit snapshots follow the HIPAA/NYDFS window.
# Off-host repository URLs are refused. This service has no egress.
set -euo pipefail

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
# shellcheck disable=SC1091
. "${script_dir}/restic-env.sh"
data_root="${LOCAL_AI_DATA_ROOT:-/var/lib/local-ai-stack}"

install -d -m 0700 "${data_root}/backups" "${data_root}/backups/cache"
canary="${data_root}/backups/canary"
printf '%s\n' "local-ai-stack-backup-canary" >"$canary"
chmod 0644 "$canary"

staging="${data_root}/backups/staging"
if [[ "${BACKUPS_REQUIRE_POSTGRES:-1}" == "1" ]]; then
  if ! /usr/bin/pg_isready -h /var/run/postgresql -q; then
    echo "postgres is not accepting local connections" >&2
    exit 1
  fi
  install -d -m 0770 -o root -g postgres "$staging"
  /usr/sbin/runuser -u postgres -- /usr/bin/pg_dump -Fc -d litellm -f "${staging}/litellm.dump"
  chown root:root "${staging}/litellm.dump"
  chmod 0600 "${staging}/litellm.dump"
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
    --keep-daily "${RESTIC_KEEP_DAILY_EPHI:-30}"
fi

"$RESTIC_BIN" forget --tag audit --prune \
  --keep-daily "${RESTIC_KEEP_DAILY_AUDIT:-7}" \
  --keep-weekly "${RESTIC_KEEP_WEEKLY_AUDIT:-4}" \
  --keep-monthly "${RESTIC_KEEP_MONTHLY_AUDIT:-60}" \
  --keep-yearly "${RESTIC_KEEP_YEARLY_AUDIT:-6}"

if [[ -n "${RESTIC_OFFSITE_REPOSITORY:-}" ]]; then
  if ! "$RESTIC_BIN" -r "$RESTIC_OFFSITE_REPOSITORY" cat config >/dev/null 2>&1; then
    "$RESTIC_BIN" -r "$RESTIC_OFFSITE_REPOSITORY" init
  fi
  "$RESTIC_BIN" copy --repo2 "$RESTIC_OFFSITE_REPOSITORY"
fi

echo "restic backup complete"
