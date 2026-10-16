#!/usr/bin/env bash
# Idempotent apt source for Caddy. WireGuard comes from Ubuntu.
# The Caddy key fingerprint is the primary key Cloudsmith publishes for
# caddy/stable: https://cloudsmith.io/~caddy/repos/stable/pub-keys/
# A re-apply fetches the key through the apt proxy on 127.0.0.1:8890.
set -euo pipefail

caddy_fingerprint="65760C51EDEA2017CEA2CA15155B6D79CA56EA34"
keyring="/usr/share/keyrings/caddy-stable-archive-keyring.gpg"
armored="$(mktemp)"
binary="$(mktemp)"
cleanup() {
  rm -f "$armored" "$binary"
}
trap cleanup EXIT

install -d -m 0755 /usr/share/keyrings /etc/apt/sources.list.d

curl_proxy=()
if [[ -f /etc/apt/apt.conf.d/99local-ai-proxy ]]; then
  curl_proxy=(--proxy http://127.0.0.1:8890)
fi

curl "${curl_proxy[@]}" -fsSL https://dl.cloudsmith.io/public/caddy/stable/gpg.key -o "$armored"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
actual="$(gpg --show-keys --with-colons "$armored" | bash "$script_dir/caddy-key.sh")"
if [[ "$actual" != "$caddy_fingerprint" ]]; then
  echo "caddy apt key fingerprint mismatch" >&2
  exit 1
fi
gpg --dearmor -o "$binary" "$armored"
install -m 0644 "$binary" "$keyring"

cat > /etc/apt/sources.list.d/caddy-stable.list <<'EOF'
# Source: Caddy
# Site: https://github.com/caddyserver/caddy
# Repository: Caddy / stable
# Description: Fast, multi-platform web server with automatic HTTPS

deb [signed-by=/usr/share/keyrings/caddy-stable-archive-keyring.gpg] https://dl.cloudsmith.io/public/caddy/stable/deb/debian any-version main

deb-src [signed-by=/usr/share/keyrings/caddy-stable-archive-keyring.gpg] https://dl.cloudsmith.io/public/caddy/stable/deb/debian any-version main
EOF

rm -f /etc/apt/sources.list.d/cloudflared.list /usr/share/keyrings/cloudflare-main.gpg
