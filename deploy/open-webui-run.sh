#!/usr/bin/env bash
# Load Open WebUI credentials from systemd LoadCredential. Do not print them.
set -euo pipefail

if [[ $- == *x* ]]; then
  echo "refusing to start with xtrace" >&2
  exit 1
fi

if [[ "${MICROSOFT_CLIENT_ID:-}" == "00000000-0000-0000-0000-000000000000" ]]; then
  echo "refusing zero-GUID MICROSOFT_CLIENT_ID" >&2
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
MICROSOFT_CLIENT_SECRET="$(read_cred microsoft_client_secret)"
# Gateway credential only. This is not a LiteLLM virtual key and cannot call :4000.
OPENAI_API_KEY="$(read_cred gateway_client_key)"
export WEBUI_SECRET_KEY MICROSOFT_CLIENT_SECRET OPENAI_API_KEY
# An empty file means the bootstrap password was removed after an Entra admin existed.
WEBUI_ADMIN_PASSWORD="$(read_cred webui_admin_password)"
if [[ -n "$WEBUI_ADMIN_PASSWORD" ]]; then
  export WEBUI_ADMIN_PASSWORD
else
  unset WEBUI_ADMIN_PASSWORD
fi
exec "${OPEN_WEBUI_BIN:-/opt/open-webui/venv/bin/open-webui}" serve --host 127.0.0.1 --port 8080
