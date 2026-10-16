#!/usr/bin/env bash
# Encrypted restic backup. The password file is root-only and is not in git.
# ePHI snapshots are kept 30 days. Audit snapshots follow the HIPAA/NYDFS window.
set -euo pipefail

env_file="${LOCAL_AI_RESTIC_ENV:-/etc/restic/local-ai.env}"
if [[ ! -f "$env_file" ]]; then
  echo "restic backup skipped: ${env_file} is absent" >&2
  exit 0
fi

set -a
# shellcheck disable=SC1090
. "$env_file"
set +a

data_root="${LOCAL_AI_DATA_ROOT:-/var/lib/local-ai-stack}"
password_file="${RESTIC_PASSWORD_FILE:-}"

if [[ -z "${RESTIC_REPOSITORY:-}" || -z "$password_file" || ! -e "$password_file" ]]; then
  echo "restic backup skipped: repository is not configured" >&2
  exit 0
fi
if [[ ! -s "$password_file" ]]; then
  echo "restic password file is empty" >&2
  exit 1
fi
password_mode="$(stat -c %a "$password_file")"
password_owner="$(stat -c %U "$password_file")"
if [[ "$password_mode" != "600" || "$password_owner" != "root" ]]; then
  echo "restic password file must be mode 0600 and owned by root" >&2
  exit 1
fi

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

export RESTIC_PASSWORD_FILE="$password_file"
export RESTIC_CACHE_DIR="${RESTIC_CACHE_DIR:-${data_root}/backups/cache}"

if ! /usr/bin/restic cat config >/dev/null 2>&1; then
  /usr/bin/restic init
fi

audit_paths=("$canary")
if [[ -f "${staging}/litellm.dump" ]]; then
  audit_paths+=("${staging}/litellm.dump")
fi
/usr/bin/restic backup --tag audit --tag local-ai-stack "${audit_paths[@]}"

if [[ -d "${data_root}/webui" ]]; then
  /usr/bin/restic backup --tag ephi --tag local-ai-stack \
    --exclude "${data_root}/webui/hf" \
    --exclude "${data_root}/webui/st" \
    "${data_root}/webui"
  /usr/bin/restic forget --tag ephi --prune \
    --keep-daily "${RESTIC_KEEP_DAILY_EPHI:-30}"
fi

/usr/bin/restic forget --tag audit --prune \
  --keep-daily "${RESTIC_KEEP_DAILY_AUDIT:-7}" \
  --keep-weekly "${RESTIC_KEEP_WEEKLY_AUDIT:-4}" \
  --keep-monthly "${RESTIC_KEEP_MONTHLY_AUDIT:-60}" \
  --keep-yearly "${RESTIC_KEEP_YEARLY_AUDIT:-6}"

if [[ -n "${RESTIC_OFFSITE_REPOSITORY:-}" ]]; then
  if ! /usr/bin/restic -r "$RESTIC_OFFSITE_REPOSITORY" cat config >/dev/null 2>&1; then
    /usr/bin/restic -r "$RESTIC_OFFSITE_REPOSITORY" init
  fi
  /usr/bin/restic copy --repo2 "$RESTIC_OFFSITE_REPOSITORY"
fi

echo "restic backup complete"
