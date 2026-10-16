#!/usr/bin/env bash
# Host baseline for a Proxmox Ubuntu Server LTS guest. Idempotent.
# --check validates this directory and does not change the host.
# --apply requires root. --skip-ufw leaves the firewall to host/ufw.sh,
# which must run after the service accounts exist.
set -euo pipefail

HOST="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODE="apply"
SKIP_UFW=0

for arg in "$@"; do
  case "$arg" in
    --check) MODE="check" ;;
    --apply) MODE="apply" ;;
    --skip-ufw) SKIP_UFW=1 ;;
    *)
      echo "usage: $0 [--check|--apply] [--skip-ufw]" >&2
      exit 2
      ;;
  esac
done

if [[ "$MODE" == "check" ]]; then
  bash -n "$HOST/install.sh"
  bash -n "$HOST/ufw.sh"
  bash -n "$HOST/luks-data.sh"
  bash -n "$HOST/secrets/populate.sh"
  grep -q 'default deny incoming' "$HOST/ufw.sh"
  grep -q 'default deny outgoing' "$HOST/ufw.sh"
  grep -q 'egress_owners.py' "$HOST/ufw.sh"
  grep -q 'read -r -s' "$HOST/secrets/populate.sh"
  grep -q '0600' "$HOST/secrets/populate.sh"
  grep -q 'PasswordAuthentication no' "$HOST/ssh/00-local-ai-vpn.conf"
  grep -q 'PermitRootLogin no' "$HOST/ssh/00-local-ai-vpn.conf"
  grep -q 'net.ipv4.conf.all.rp_filter = 1' "$HOST/sysctl/99-local-ai-cis.conf"
  grep -q 'guest-exec' "$HOST/systemd/qemu-guest-agent.override.conf"
  grep -q -- '-security' "$HOST/apt/52local-ai-unattended"
  if grep -R -n 'docker\.io' "$HOST" --exclude="$(basename "$0")" --exclude='README.md'; then
    echo "host scripts must not install Docker" >&2
    exit 1
  fi
  echo "host check ok"
  exit 0
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "apply requires root" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y \
  qemu-guest-agent \
  cryptsetup \
  libpam-pwquality \
  auditd \
  audispd-plugins \
  unattended-upgrades \
  apt-listchanges \
  apparmor \
  apparmor-utils \
  ufw

install -m 0644 "$HOST/apt/20auto-upgrades" /etc/apt/apt.conf.d/20auto-upgrades
install -m 0644 "$HOST/apt/52local-ai-unattended" /etc/apt/apt.conf.d/52local-ai-unattended
install -m 0644 "$HOST/sysctl/99-local-ai-cis.conf" /etc/sysctl.d/99-local-ai-cis.conf
sysctl --system >/dev/null || true

install -d -m 0755 /etc/ssh/sshd_config.d
install -m 0644 "$HOST/ssh/00-local-ai-vpn.conf" /etc/ssh/sshd_config.d/00-local-ai-vpn.conf
if [[ -n "${SSH_ALLOW_USERS:-}" ]]; then
  if [[ ! "${SSH_ALLOW_USERS}" =~ ^[A-Za-z0-9._-]+([[:space:]][A-Za-z0-9._-]+)*$ ]]; then
    echo "SSH_ALLOW_USERS must be account names" >&2
    exit 1
  fi
  printf 'AllowUsers %s\n' "$SSH_ALLOW_USERS" > /etc/ssh/sshd_config.d/10-allow-users.conf
  chmod 0644 /etc/ssh/sshd_config.d/10-allow-users.conf
fi

install -d -m 0755 /etc/audit/rules.d
install -m 0640 "$HOST/audit/99-local-ai.rules" /etc/audit/rules.d/99-local-ai.rules
augenrules --load >/dev/null 2>&1 || true
systemctl enable auditd || true

if [[ -x /usr/sbin/qemu-ga ]]; then
  install -d -m 0755 /etc/systemd/system/qemu-guest-agent.service.d
  install -m 0644 "$HOST/systemd/qemu-guest-agent.override.conf" \
    /etc/systemd/system/qemu-guest-agent.service.d/10-restrict.conf
  systemctl daemon-reload
  systemctl enable qemu-guest-agent.service
  systemctl restart qemu-guest-agent.service || true
fi

install -d -m 0755 /etc/security/pwquality.conf.d /etc/modprobe.d /etc/profile.d /etc/sudoers.d
install -m 0644 "$HOST/cis/99-local-ai-pwquality.conf" /etc/security/pwquality.conf.d/99-local-ai.conf
install -m 0644 "$HOST/cis/99-local-ai-modules.conf" /etc/modprobe.d/99-local-ai-cis.conf
install -m 0644 "$HOST/cis/99-local-ai-timeout.sh" /etc/profile.d/99-local-ai-timeout.sh
install -m 0440 "$HOST/cis/99-local-ai-sudoers" /etc/sudoers.d/99-local-ai
visudo -cf /etc/sudoers.d/99-local-ai >/dev/null
install -m 0644 "$HOST/cis/issue.net" /etc/issue.net

python3 - "$HOST/cis/login.defs.keys" <<'PY'
import pathlib, sys
keys = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
path = pathlib.Path("/etc/login.defs")
text = path.read_text(encoding="utf-8") if path.exists() else ""
lines = text.splitlines()
wanted = {}
for raw in keys.splitlines():
    if not raw.strip() or raw.startswith("#"):
        continue
    name, value = raw.split(None, 1)
    wanted[name] = value
seen = set()
out = []
for line in lines:
    parts = line.split()
    if parts and parts[0] in wanted:
        out.append(f"{parts[0]} {wanted[parts[0]]}")
        seen.add(parts[0])
    else:
        out.append(line)
for name, value in wanted.items():
    if name not in seen:
        out.append(f"{name} {value}")
path.write_text("\n".join(out) + "\n", encoding="utf-8")
PY

if [[ -f /etc/security/faillock.conf ]]; then
  python3 - "$HOST/cis/faillock.keys" <<'PY'
import pathlib, sys
wanted = {}
for raw in pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").splitlines():
    if not raw.strip() or raw.startswith("#"):
        continue
    name, value = raw.split(None, 1)
    wanted[name] = value
path = pathlib.Path("/etc/security/faillock.conf")
lines = path.read_text(encoding="utf-8").splitlines()
seen = set()
out = []
for line in lines:
    stripped = line.strip()
    name = stripped.split("=", 1)[0].strip() if "=" in stripped else ""
    if name in wanted:
        out.append(f"{name} = {wanted[name]}")
        seen.add(name)
    else:
        out.append(line)
for name, value in wanted.items():
    if name not in seen:
        out.append(f"{name} = {value}")
path.write_text("\n".join(out) + "\n", encoding="utf-8")
PY
fi

chmod 0644 /etc/passwd /etc/group || true
if getent group shadow >/dev/null; then
  chown root:shadow /etc/shadow /etc/gshadow || true
  chmod 0640 /etc/shadow /etc/gshadow || true
fi

if [[ -f /etc/docker/daemon.json ]] && grep -q 'tcp://' /etc/docker/daemon.json; then
  echo "refusing to leave a Docker TCP socket configured" >&2
  exit 1
fi

if [[ "$SKIP_UFW" -eq 0 ]] && id policy-gateway >/dev/null 2>&1; then
  bash "$HOST/ufw.sh"
fi

echo "host apply complete"
