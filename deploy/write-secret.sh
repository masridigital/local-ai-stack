#!/usr/bin/env bash
# write-secret.sh DEST ENV_NAME
# Copies one environment variable into a root-only file. Prints nothing.
set -euo pipefail

if [[ "$#" -ne 2 ]]; then
  echo "usage: write-secret.sh DEST ENV_NAME" >&2
  exit 2
fi

dest="$1"
name="$2"
value="${!name:-}"
if [[ -z "$value" ]]; then
  exit 0
fi

install -d -m 0700 -o root -g root "$(dirname "$dest")"
umask 077
printf '%s' "$value" >"$dest"
chown root:root "$dest"
chmod 0600 "$dest"
