#!/bin/bash
# Export Docker secrets for Open WebUI. Do not print secret values.
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

read_secret /run/secrets/webui_secret_key WEBUI_SECRET_KEY
read_secret /run/secrets/microsoft_client_secret MICROSOFT_CLIENT_SECRET
read_secret /run/secrets/litellm_virtual_key OPENAI_API_KEY

cd /app/backend
exec bash start.sh
