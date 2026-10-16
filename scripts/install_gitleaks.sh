#!/usr/bin/env bash
# Install one pinned gitleaks binary after sha256sum against the published checksums.
# usage: install_gitleaks.sh DEST
set -euo pipefail

if [[ "$#" -ne 1 ]]; then
  echo "usage: install_gitleaks.sh DEST" >&2
  exit 2
fi

version="8.24.3"
asset="gitleaks_${version}_linux_x64.tar.gz"
# Pin matches gitleaks_8.24.3_checksums.txt from the v8.24.3 release.
expected="9991e0b2903da4c8f6122b5c3186448b927a5da4deef1fe45271c3793f4ee29c"
base="https://github.com/gitleaks/gitleaks/releases/download/v${version}"
dest="$1"

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT
cd "$workdir"

curl -fsSL -o "$asset" "${base}/${asset}"
curl -fsSL -o "gitleaks_${version}_checksums.txt" "${base}/gitleaks_${version}_checksums.txt"

if ! grep -qx "${expected}  ${asset}" "gitleaks_${version}_checksums.txt"; then
  echo "published checksum for ${asset} does not match the pinned digest" >&2
  exit 1
fi
sha256sum --ignore-missing -c "gitleaks_${version}_checksums.txt"

tar -xzf "$asset" gitleaks
install -m 0755 gitleaks "$dest"
"$dest" version
