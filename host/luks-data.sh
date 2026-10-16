#!/usr/bin/env bash
# Put /var/lib/local-ai-stack on LUKS. A Proxmox full-disk install already
# satisfies this. Otherwise set LUKS_DISK to a spare VirtIO disk.
# The passphrase is read from a hidden prompt or LUKS_PASSPHRASE and is never echoed.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA_DIR="/var/lib/local-ai-stack"
MAPPER="${LUKS_MAPPER_NAME:-local-ai-data}"

if [[ "${1:-}" == "--check" ]]; then
  bash -n "$0"
  grep -q 'read -r -s' "$0"
  grep -q 'LUKS_FORMAT_CONFIRM' "$0"
  exit 0
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "luks apply requires root" >&2
  exit 1
fi

case $- in
  *x*)
    echo "refusing to open LUKS with xtrace" >&2
    exit 1
    ;;
esac

if python3 "$ROOT/scripts/check_luks.py" --target "$DATA_DIR" >/dev/null 2>&1; then
  echo "luks already covers ${DATA_DIR}"
  exit 0
fi

if [[ -z "${LUKS_DISK:-}" ]]; then
  echo "${DATA_DIR} is not on LUKS. Encrypt the VM disk in the Ubuntu installer or set LUKS_DISK." >&2
  exit 1
fi

disk="$LUKS_DISK"
if [[ ! -b "$disk" ]]; then
  echo "LUKS_DISK is not a block device" >&2
  exit 1
fi

root_source="$(findmnt -n -o SOURCE /)"
root_disk="$(lsblk -ndo PKNAME "$root_source" 2>/dev/null || true)"
disk_base="$(basename "$disk")"
if [[ -n "$root_disk" && "$disk_base" == "$root_disk" ]]; then
  echo "refusing to format the root disk" >&2
  exit 1
fi
if findmnt -n -S "$disk" >/dev/null 2>&1; then
  echo "refusing to format a mounted disk" >&2
  exit 1
fi

read_passphrase() {
  if [[ -n "${LUKS_PASSPHRASE:-}" ]]; then
    printf '%s' "$LUKS_PASSPHRASE"
    return 0
  fi
  if [[ ! -t 0 ]]; then
    echo "set LUKS_PASSPHRASE or run from a terminal" >&2
    exit 1
  fi
  local first="" second=""
  printf 'LUKS passphrase (input hidden): ' >&2
  IFS= read -r -s first || true
  printf '\n' >&2
  printf 'Confirm LUKS passphrase (input hidden): ' >&2
  IFS= read -r -s second || true
  printf '\n' >&2
  if [[ -z "$first" || "$first" != "$second" ]]; then
    echo "passphrase not accepted" >&2
    exit 1
  fi
  printf '%s' "$first"
}

pass="$(read_passphrase)"
if ! cryptsetup isLuks "$disk"; then
  if [[ "${LUKS_FORMAT_CONFIRM:-}" != "$disk" ]]; then
    echo "refusing to format ${disk} without LUKS_FORMAT_CONFIRM set to that device" >&2
    exit 1
  fi
  printf '%s' "$pass" | cryptsetup luksFormat --type luks2 --batch-mode "$disk" --key-file -
fi

if [[ ! -e "/dev/mapper/${MAPPER}" ]]; then
  printf '%s' "$pass" | cryptsetup luksOpen "$disk" "$MAPPER" --key-file -
fi
unset pass LUKS_PASSPHRASE

if ! blkid "/dev/mapper/${MAPPER}" >/dev/null 2>&1; then
  mkfs.ext4 -q "/dev/mapper/${MAPPER}"
fi

install -d -m 0755 "$DATA_DIR"
if [[ -n "$(ls -A "$DATA_DIR" 2>/dev/null || true)" ]] && ! mountpoint -q "$DATA_DIR"; then
  staging="$(mktemp -d)"
  mount "/dev/mapper/${MAPPER}" "$staging"
  cp -a "${DATA_DIR}/." "$staging/"
  umount "$staging"
  rmdir "$staging"
fi
if ! mountpoint -q "$DATA_DIR"; then
  mount "/dev/mapper/${MAPPER}" "$DATA_DIR"
fi

uuid="$(blkid -s UUID -o value "$disk")"
crypt_line="${MAPPER} UUID=${uuid} none luks"
fstab_line="/dev/mapper/${MAPPER} ${DATA_DIR} ext4 defaults,noatime 0 2"
grep -qF "$crypt_line" /etc/crypttab 2>/dev/null || printf '%s\n' "$crypt_line" >> /etc/crypttab
grep -qF "$fstab_line" /etc/fstab || printf '%s\n' "$fstab_line" >> /etc/fstab
echo "luks data volume ready"
