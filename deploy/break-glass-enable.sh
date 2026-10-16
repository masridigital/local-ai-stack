#!/usr/bin/env bash
# Break-glass check. This does not enable a password login.
# The secret stays in the file. It is never printed and never passed as an argument.
set -euo pipefail

if [[ "$#" -ne 0 ]]; then
  echo "do not pass secrets on the command line" >&2
  exit 2
fi

if [[ -z "${BREAK_GLASS_SECRET_FILE:-}" ]]; then
  echo "set BREAK_GLASS_SECRET_FILE to a root-owned 0600 file" >&2
  exit 2
fi

if [[ ! -f "${BREAK_GLASS_SECRET_FILE}" ]]; then
  echo "break-glass secret file is missing" >&2
  exit 2
fi

mode="$(stat -c '%a' "${BREAK_GLASS_SECRET_FILE}")"
if [[ "${mode}" != "600" ]]; then
  echo "break-glass secret file must be mode 0600" >&2
  exit 2
fi

if [[ -n "${BREAK_GLASS_AUDIT_LOG:-}" ]]; then
  printf '%s break-glass checked; password login was not enabled\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"${BREAK_GLASS_AUDIT_LOG}"
fi

echo "break-glass does not enable login; ENABLE_LOGIN_FORM stays false" >&2
exit 1
