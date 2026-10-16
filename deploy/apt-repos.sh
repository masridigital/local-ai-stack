#!/usr/bin/env bash
# Idempotent apt sources for Caddy. cloudflared is fetched only until the package
# is installed; the origin is not a steady-state egress destination.
set -euo pipefail

install -d -m 0755 /usr/share/keyrings /etc/apt/sources.list.d

curl_proxy=()
if [[ -f /etc/apt/apt.conf.d/99local-ai-proxy ]]; then
  curl_proxy=(--proxy http://127.0.0.1:8890)
fi

if [[ ! -s /usr/share/keyrings/caddy-stable-archive-keyring.gpg ]]; then
  curl "${curl_proxy[@]}" -fsSL https://dl.cloudsmith.io/public/caddy/stable/gpg.key \
    | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
fi
curl "${curl_proxy[@]}" -fsSL https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt \
  -o /etc/apt/sources.list.d/caddy-stable.list

if dpkg -s cloudflared >/dev/null 2>&1; then
  rm -f /etc/apt/sources.list.d/cloudflared.list
else
  if [[ ! -s /usr/share/keyrings/cloudflare-main.gpg ]]; then
    curl "${curl_proxy[@]}" -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg \
      | gpg --dearmor -o /usr/share/keyrings/cloudflare-main.gpg
  fi
  printf '%s\n' 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main' \
    > /etc/apt/sources.list.d/cloudflared.list
fi
