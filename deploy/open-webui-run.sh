#!/usr/bin/env bash
# Load Open WebUI credentials from systemd LoadCredential. Do not print them.
set -euo pipefail

if [[ $- == *x* ]]; then
  echo "refusing to start with xtrace" >&2
  exit 1
fi

cred="${CREDENTIALS_DIRECTORY:?}"

read_cred() {
  local file="$1"
  if [[ ! -f "${cred}/${file}" ]]; then
    echo "missing credential ${file}" >&2
    exit 1
  fi
  printf '%s' "$(<"${cred}/${file}")"
}

WEBUI_SECRET_KEY="$(read_cred webui_secret_key)"
WEBUI_ADMIN_PASSWORD="$(read_cred webui_admin_password)"
MICROSOFT_CLIENT_SECRET="$(read_cred microsoft_client_secret)"
# Gateway credential only. This is not a LiteLLM virtual key and cannot call :4000.
OPENAI_API_KEY="$(read_cred gateway_client_key)"
export WEBUI_SECRET_KEY WEBUI_ADMIN_PASSWORD MICROSOFT_CLIENT_SECRET OPENAI_API_KEY
exec "${OPEN_WEBUI_BIN:-/opt/open-webui/venv/bin/open-webui}" serve --host 127.0.0.1 --port 8080
