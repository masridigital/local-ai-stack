#!/usr/bin/env bash
# Load Open WebUI credentials from systemd LoadCredential. Do not print them.
set -euo pipefail

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
OPENAI_API_KEY="$(read_cred litellm_virtual_key)"
export WEBUI_SECRET_KEY MICROSOFT_CLIENT_SECRET OPENAI_API_KEY
exec /opt/open-webui/venv/bin/open-webui serve --host 127.0.0.1 --port 8080
