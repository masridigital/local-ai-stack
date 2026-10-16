#!/usr/bin/env bash
# Load LiteLLM credentials from systemd LoadCredential. Do not print them.
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

LITELLM_MASTER_KEY="$(read_cred litellm_master_key)"
ANTHROPIC_API_KEY="$(read_cred anthropic_api_key)"
AZURE_CLIENT_SECRET="$(read_cred azure_client_secret)"
DATABASE_URL="$(read_cred database_url)"
export LITELLM_MASTER_KEY ANTHROPIC_API_KEY AZURE_CLIENT_SECRET DATABASE_URL
export LITELLM_LOG=ERROR
exec /opt/litellm/venv/bin/litellm --config /opt/litellm/config.yaml --host 127.0.0.1 --port 4000
