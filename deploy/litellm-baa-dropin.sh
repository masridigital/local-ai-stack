#!/usr/bin/env bash
# Install or remove the LiteLLM Anthropic LoadCredential drop-in.
# Usage: litellm-baa-dropin.sh <true|other> <dest-dir> <source-file>
set -euo pipefail

switch="${1:?}"
dest="${2:?}"
src="${3:?}"
install -d -m 0755 "$dest"
target="${dest}/10-anthropic.conf"
if [[ "$switch" == "true" ]]; then
  install -m 0644 "$src" "$target"
else
  rm -f "$target"
fi
