#!/usr/bin/env bash
# Re-resolve egress destinations and refresh the owner rules.
# Install-time allows stay off. systemd starts this from the refresh timer.
set -euo pipefail

unset INSTALL_EGRESS
root="${LOCAL_AI_ROOT:?}"
python3 "$root/scripts/egress_owners.py" --apply-ufw --dest "$root/deploy/egress-destinations.yaml"
ufw reload
echo "egress refreshed"
