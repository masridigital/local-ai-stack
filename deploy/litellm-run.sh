#!/usr/bin/env bash
# Load LiteLLM credentials from systemd LoadCredential. Do not print them.
set -euo pipefail

if [[ $- == *x* ]]; then
  echo "refusing to start with xtrace" >&2
  exit 1
fi

cred="${CREDENTIALS_DIRECTORY:?}"
bind_host="${BIND_HOST:-127.0.0.2}"
case "$bind_host" in
  ::|::0|::*|0.*)
    echo "refusing wildcard bind" >&2
    exit 1
    ;;
esac

read_cred() {
  local file="$1"
  if [[ ! -f "${cred}/${file}" ]]; then
    echo "missing credential ${file}" >&2
    exit 1
  fi
  printf '%s' "$(<"${cred}/${file}")"
}

LITELLM_MASTER_KEY="$(read_cred litellm_master_key)"
AZURE_API_KEY="$(read_cred azure_api_key)"
DATABASE_URL="$(read_cred database_url)"
export LITELLM_MASTER_KEY AZURE_API_KEY DATABASE_URL
# The Anthropic key file is written only when ANTHROPIC_BAA_ENABLED=true.
if [[ -f "${cred}/anthropic_api_key" ]]; then
  ANTHROPIC_API_KEY="$(read_cred anthropic_api_key)"
  export ANTHROPIC_API_KEY
fi
export LITELLM_LOG=ERROR
exec "${LITELLM_BIN:-/opt/litellm/venv/bin/litellm}" --config /opt/litellm/config.yaml --host "$bind_host" --port 4000
