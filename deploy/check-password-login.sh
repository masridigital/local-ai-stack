#!/usr/bin/env bash
# Confirm this VM refuses password login.
# --sshd-text reads a saved `sshd -T` dump. --live asks the local sshd.
# Open WebUI password sign-in must answer HTTP 403 when it is up.
set -euo pipefail

live=0
allow_down=0
webui_url="http://127.0.0.1:8080"
sshd_text=""

usage() {
  echo "usage: check-password-login.sh (--live | --sshd-text FILE) [--webui URL] [--allow-down]" >&2
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --live) live=1 ;;
    --allow-down) allow_down=1 ;;
    --webui)
      webui_url="${2:-}"
      shift
      ;;
    --sshd-text)
      sshd_text="${2:-}"
      shift
      ;;
    *) usage ;;
  esac
  shift
done

if [[ -n "$sshd_text" ]]; then
  text="$(<"$sshd_text")"
elif [[ "$live" -eq 1 ]]; then
  text="$(sshd -T)"
else
  usage
fi

lower="$(printf '%s\n' "$text" | tr '[:upper:]' '[:lower:]')"
if ! grep -Eq '^passwordauthentication[[:space:]]+no$' <<<"$lower"; then
  echo "password login is not refused" >&2
  exit 1
fi

code="000"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
if curl -sS -o /dev/null -w '%{http_code}' --max-time 2 \
  -X POST "${webui_url}/api/v1/auths/signin" \
  -H 'Content-Type: application/json' \
  -d '{"email":"synthetic@example.invalid","password":"synthetic-not-a-password"}' >"$tmp"; then
  code="$(<"$tmp")"
fi
if [[ "$code" == "000" ]]; then
  if [[ "$allow_down" -eq 1 ]]; then
    echo "password login is refused"
    exit 0
  fi
  echo "open webui did not answer the password login check" >&2
  exit 1
fi
if [[ "$code" != "403" ]]; then
  echo "password login was not refused" >&2
  exit 1
fi
echo "password login is refused"
