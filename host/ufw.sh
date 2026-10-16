#!/usr/bin/env bash
# Default deny in and out. Per-user egress is a resolved address set in UFW,
# which Ubuntu applies through nftables. systemd IPAddressAllow hostnames are not used.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ "${1:-}" == "--check" ]]; then
  exit 0
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "ufw apply requires root" >&2
  exit 1
fi

forbidden_cidr() {
  local cidr="$1"
  local world
  world="$(printf '%s.%s.%s.%s/0' 0 0 0 0)"
  [[ "$cidr" == "$world" || "$cidr" == "any" || "$cidr" == "::/0" ]]
}

ufw default deny incoming
ufw default deny outgoing
ufw allow in on lo
ufw allow out on lo
ufw logging low

if [[ -n "${VPN_SSH_CIDR:-}" ]]; then
  if forbidden_cidr "$VPN_SSH_CIDR"; then
    echo "VPN_SSH_CIDR must be the VPN, not the whole internet" >&2
    exit 1
  fi
  if [[ ! "$VPN_SSH_CIDR" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$ ]]; then
    echo "VPN_SSH_CIDR must be an IPv4 prefix" >&2
    exit 1
  fi
  ufw allow from "$VPN_SSH_CIDR" to any port 22 proto tcp
  ufw allow from "$VPN_SSH_CIDR" to any port 443 proto tcp
fi

if [[ -n "${WIREGUARD_LISTEN_PORT:-}" ]]; then
  if [[ ! "$WIREGUARD_LISTEN_PORT" =~ ^[0-9]+$ ]]; then
    echo "WIREGUARD_LISTEN_PORT must be numeric" >&2
    exit 1
  fi
  ufw allow "${WIREGUARD_LISTEN_PORT}/udp"
fi

if [[ -z "${DNS_SERVERS:-}" && -r /run/systemd/resolve/resolv.conf ]]; then
  discovered="$(awk '/^nameserver / && $2 !~ /^127\./ { print $2; exit }' /run/systemd/resolve/resolv.conf)"
  if [[ -n "${discovered}" ]]; then
    export DNS_SERVERS="$discovered"
  fi
fi

# Drop the install-time allows (PyPI, GitHub, Hugging Face) even if the caller exported them.
# ANTHROPIC_BAA_ENABLED=true is what adds api.anthropic.com for the litellm user.
unset INSTALL_EGRESS
python3 "$ROOT/scripts/egress_owners.py" --apply-ufw --dest "$ROOT/deploy/egress-destinations.yaml"
ufw --force enable
echo "ufw applied"
