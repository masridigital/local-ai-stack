#!/usr/bin/env bash
# Write root-only secret files. Prompts are hidden. Values are never echoed.
# Existing 0600 files are left in place. HOST_SECRET_ROOT relocates the tree for tests.
set -euo pipefail

if [[ $- == *x* ]]; then
  echo "refusing to populate secrets with xtrace" >&2
  exit 1
fi

SECRET_ROOT="${HOST_SECRET_ROOT:-}"

if [[ "${1:-}" == "--check" ]]; then
  grep -q 'read -r -s' "$0"
  grep -q '0600' "$0"
  echo "secret populate check ok"
  exit 0
fi

install_dir() {
  local dir="$1"
  if [[ "$(id -u)" -eq 0 ]]; then
    install -d -m 0700 -o root -g root "$dir"
  else
    install -d -m 0700 "$dir"
  fi
}

write_secret() {
  local dest="$1"
  local value="$2"
  install_dir "$(dirname "$dest")"
  printf '%s' "$value" | SECRET_DEST="$dest" python3 -c '
import os, pathlib, sys
dest = pathlib.Path(os.environ["SECRET_DEST"])
data = sys.stdin.buffer.read()
dest.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
os.chmod(dest.parent, 0o700)
tmp = dest.with_name(dest.name + ".tmp")
fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
try:
    os.write(fd, data)
finally:
    os.close(fd)
os.chmod(tmp, 0o600)
os.replace(tmp, dest)
os.chmod(dest, 0o600)
'
  if [[ "$(id -u)" -eq 0 ]]; then
    chown root:root "$dest"
  fi
  local mode
  mode="$(stat -c '%a' "$dest")"
  if [[ "$mode" != "600" ]]; then
    echo "refusing a secret file that is not mode 0600" >&2
    exit 1
  fi
}

ensure_mode() {
  local dest="$1"
  if [[ ! -f "$dest" ]]; then
    return 1
  fi
  chmod 0600 "$dest"
  if [[ "$(id -u)" -eq 0 ]]; then
    chown root:root "$dest"
  fi
  return 0
}

prompt_secret() {
  local label="$1"
  local first="" second=""
  printf 'Enter %s (input hidden): ' "$label" >&2
  IFS= read -r -s first || true
  printf '\n' >&2
  printf 'Confirm %s (input hidden): ' "$label" >&2
  IFS= read -r -s second || true
  printf '\n' >&2
  if [[ -z "$first" || "$first" != "$second" ]]; then
    echo "secret not written" >&2
    exit 1
  fi
  printf '%s' "$first"
}

fill_external() {
  local dest="$1"
  local envname="$2"
  local label="$3"
  if ensure_mode "$dest"; then
    return 0
  fi
  local value="${!envname:-}"
  if [[ -z "$value" && -t 0 ]]; then
    value="$(prompt_secret "$label")"
  fi
  if [[ -z "$value" ]]; then
    echo "secret file missing: ${dest#"$SECRET_ROOT"}" >&2
    return 0
  fi
  write_secret "$dest" "$value"
  unset value
}

generate() {
  python3 -c 'import secrets; print(secrets.token_hex(32), end="")'
}

copy_secret() {
  local src="$1"
  local dest="$2"
  if [[ -f "$dest" || ! -f "$src" ]]; then
    return 0
  fi
  install_dir "$(dirname "$dest")"
  install -m 0600 "$src" "$dest"
  if [[ "$(id -u)" -eq 0 ]]; then
    chown root:root "$dest"
  fi
}

fill_generated() {
  local dest="$1"
  if ensure_mode "$dest"; then
    return 0
  fi
  write_secret "$dest" "$(generate)"
}

postgres="${SECRET_ROOT}/etc/postgres/postgres_password"
master="${SECRET_ROOT}/etc/litellm/litellm_master_key"
webui="${SECRET_ROOT}/etc/open-webui/webui_secret_key"
admin_pw="${SECRET_ROOT}/etc/open-webui/webui_admin_password"
gateway="${SECRET_ROOT}/etc/policy-gateway/gateway_client_key"
gateway_copy="${SECRET_ROOT}/etc/open-webui/gateway_client_key"
virtual="${SECRET_ROOT}/etc/policy-gateway/litellm_virtual_key"
dburl="${SECRET_ROOT}/etc/litellm/database_url"
auditurl="${SECRET_ROOT}/etc/policy-gateway/audit_database_url"

fill_external "$postgres" POSTGRES_PASSWORD "Postgres password"
if [[ ! -f "$postgres" ]]; then
  fill_generated "$postgres"
fi
fill_generated "$master"
fill_generated "$webui"
fill_generated "$admin_pw"
fill_generated "$gateway"
copy_secret "$gateway" "$gateway_copy"

fill_external "$virtual" LITELLM_VIRTUAL_KEY "LiteLLM virtual key"
fill_external "${SECRET_ROOT}/etc/litellm/azure_api_key" AZURE_API_KEY "Azure API key"
fill_external "${SECRET_ROOT}/etc/open-webui/microsoft_client_secret" MICROSOFT_CLIENT_SECRET "Entra client secret"

if [[ -f "$postgres" && ! -f "$dburl" && -z "${DATABASE_URL:-}" ]]; then
  pw="$(<"$postgres")"
  write_secret "$dburl" "postgresql://localai:${pw}@127.0.0.1:5432/litellm"
  unset pw
else
  fill_external "$dburl" DATABASE_URL "LiteLLM database URL"
fi
copy_secret "$dburl" "$auditurl"
fill_external "$auditurl" AUDIT_DATABASE_URL "audit database URL"

echo "secrets populated"
