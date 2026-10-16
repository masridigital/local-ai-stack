#!/usr/bin/env bash
# Break-glass admin enablement. Password is read from a root-owned file, never argv.
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

echo "break-glass file accepted; rotate the credential after use and record the event in the audit log" >&2
