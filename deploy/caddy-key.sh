#!/usr/bin/env bash
# Read a `gpg --show-keys --with-colons` dump on stdin and print the
# fingerprint of the single primary key. A subkey fingerprint does not count.
set -euo pipefail

pubs=0
expect_fpr=0
primary=""

while IFS= read -r line || [[ -n "$line" ]]; do
  tag="${line%%:*}"
  if [[ "$expect_fpr" -eq 1 ]]; then
    fingerprint="$(printf '%s\n' "$line" | awk -F: '$1 == "fpr" { print $10 }')"
    if [[ "$tag" != "fpr" || -z "$fingerprint" ]]; then
      echo "caddy apt key must contain exactly one primary key" >&2
      exit 1
    fi
    primary="$fingerprint"
    expect_fpr=0
    continue
  fi
  if [[ "$tag" == "pub" ]]; then
    pubs=$((pubs + 1))
    expect_fpr=1
  fi
done

if [[ "$pubs" -ne 1 || -z "$primary" || "$expect_fpr" -eq 1 ]]; then
  echo "caddy apt key must contain exactly one primary key" >&2
  exit 1
fi

printf '%s\n' "$primary"
