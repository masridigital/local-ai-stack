#!/usr/bin/env bash
# Loopback health probes. The policy gateway on :8088 accepts only the openwebui uid.
set -euo pipefail

case "${1:-}" in
  gateway)
    if [[ "$(id -u)" -ne 0 ]]; then
      echo "gateway health check requires root so it can run as openwebui" >&2
      exit 1
    fi
    runuser -u openwebui -- curl -fsS --max-time 2 http://127.0.0.1:8088/health >/dev/null
    ;;
  *)
    echo "usage: health-check.sh gateway" >&2
    exit 2
    ;;
esac
