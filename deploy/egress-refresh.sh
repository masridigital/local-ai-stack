#!/usr/bin/env bash
# Refresh the proxy environment and the owner rules.
# Install-time allows stay off. The proxy reads FQDNs; this does not pin CDN addresses.
set -euo pipefail

unset INSTALL_EGRESS
root="${LOCAL_AI_ROOT:?}"
if [[ "${1:-}" == "--nft-only" ]]; then
  python3 "$root/scripts/egress_nft.py" | nft -f -
  exit 0
fi
install -m 0644 "$root/deploy/egress-destinations.yaml" /etc/local-ai-stack/egress-destinations.yaml
python3 "$root/scripts/egress_owners.py" --apply-ufw --dest "$root/deploy/egress-destinations.yaml"
python3 "$root/scripts/egress_nft.py" | nft -f -
ufw reload
systemctl try-restart egress-proxy.service || true
echo "egress refreshed"
