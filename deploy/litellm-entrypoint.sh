#!/bin/bash
# Export Docker secrets into the LiteLLM process. Do not print secret values.
set -euo pipefail

read_secret() {
  local file="$1"
  local var_name="$2"
  if [[ -f "$file" ]]; then
    local value
    value="$(<"$file")"
    export "${var_name}=${value}"
  fi
}

read_secret /run/secrets/litellm_master_key LITELLM_MASTER_KEY
read_secret /run/secrets/anthropic_api_key ANTHROPIC_API_KEY
read_secret /run/secrets/azure_client_secret AZURE_CLIENT_SECRET
read_secret /run/secrets/database_url DATABASE_URL

export LITELLM_LOG=ERROR
export PYTHONPATH="/app${PYTHONPATH:+:${PYTHONPATH}}"

exec litellm --config /app/config.yaml --port 4000 --host 0.0.0.0
