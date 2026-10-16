#!/usr/bin/env bash
# Idempotent Ubuntu Server LTS bootstrap for the local-ai-stack VM.
# --check validates the repo and does not change the host. --apply requires root.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="apply"

for arg in "$@"; do
  case "$arg" in
    --check) MODE="check" ;;
    --apply) MODE="apply" ;;
    *)
      echo "usage: $0 [--check|--apply]" >&2
      exit 2
      ;;
  esac
done

if [[ "$MODE" == "check" ]]; then
  python3 "$ROOT/scripts/check_tree.py"
  exit 0
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "apply requires root" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y \
  docker.io \
  ufw \
  unattended-upgrades \
  apt-listchanges \
  auditd \
  apparmor \
  openssl \
  restic \
  ca-certificates \
  curl \
  python3

if ! getent group docker >/dev/null; then
  groupadd docker
fi
if ! id localai >/dev/null 2>&1; then
  useradd --system --create-home --home-dir /var/lib/local-ai-stack --shell /usr/sbin/nologin localai
fi
usermod -aG docker localai

install -d -m 0700 \
  /opt/local-ai-stack \
  /etc/local-ai-stack \
  /etc/local-ai-stack/secrets \
  /etc/local-ai-stack/cloudflared \
  /var/lib/local-ai-stack \
  /var/lib/local-ai-stack/webui \
  /var/lib/local-ai-stack/postgres \
  /var/lib/local-ai-stack/backups \
  /var/lib/local-ai-stack/certs

install -m 0644 "$ROOT/docker-compose.yml" /opt/local-ai-stack/docker-compose.yml
rm -rf \
  /opt/local-ai-stack/litellm \
  /opt/local-ai-stack/presidio \
  /opt/local-ai-stack/stack \
  /opt/local-ai-stack/deploy \
  /opt/local-ai-stack/postgres \
  /opt/local-ai-stack/policy-gateway
cp -a "$ROOT/litellm" /opt/local-ai-stack/litellm
cp -a "$ROOT/presidio" /opt/local-ai-stack/presidio
cp -a "$ROOT/stack" /opt/local-ai-stack/stack
cp -a "$ROOT/deploy" /opt/local-ai-stack/deploy
cp -a "$ROOT/postgres" /opt/local-ai-stack/postgres
cp -a "$ROOT/policy-gateway" /opt/local-ai-stack/policy-gateway
install -m 0644 "$ROOT/requirements.txt" /opt/local-ai-stack/requirements.txt
install -m 0644 "$ROOT/deploy/cloudflared/config.yml" /etc/local-ai-stack/cloudflared/config.yml

write_secret() {
  local name="$1"
  local value="${2:-}"
  local dest="/etc/local-ai-stack/secrets/${name}"
  if [[ -z "$value" ]]; then
    return 0
  fi
  umask 077
  printf '%s' "$value" >"$dest"
  chown root:root "$dest"
  chmod 0600 "$dest"
}

write_secret postgres_password "${POSTGRES_PASSWORD:-}"
write_secret database_url "${DATABASE_URL:-}"
write_secret audit_database_url "${AUDIT_DATABASE_URL:-}"
write_secret litellm_master_key "${LITELLM_MASTER_KEY:-}"
write_secret litellm_virtual_key "${LITELLM_VIRTUAL_KEY:-}"
write_secret anthropic_api_key "${ANTHROPIC_API_KEY:-}"
write_secret azure_client_secret "${AZURE_CLIENT_SECRET:-}"
write_secret webui_secret_key "${WEBUI_SECRET_KEY:-}"
write_secret microsoft_client_secret "${MICROSOFT_CLIENT_SECRET:-}"
write_secret cloudflared_credentials.json "${CLOUDFLARED_CREDENTIALS_JSON:-}"

install -d -m 0755 /etc/docker
if [[ -f /etc/docker/daemon.json ]] && grep -q 'tcp://' /etc/docker/daemon.json; then
  echo "refusing to leave a Docker TCP socket configured" >&2
  exit 1
fi
cat >/etc/docker/daemon.json <<'EOF'
{
  "live-restore": true,
  "log-driver": "json-file",
  "log-opts": {"max-size": "10m", "max-file": "5"},
  "userland-proxy": false
}
EOF

cat >/etc/sysctl.d/99-local-ai.conf <<'EOF'
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.tcp_syncookies = 1
EOF
sysctl --system >/dev/null

cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
cat >/etc/apt/apt.conf.d/52local-ai-reboot <<'EOF'
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "03:30";
EOF

ufw default deny incoming
ufw default deny outgoing
if [[ -n "${VPN_SSH_CIDR:-}" ]]; then
  ufw allow from "${VPN_SSH_CIDR}" to any port 22 proto tcp
fi
while IFS= read -r line; do
  if [[ "$line" =~ ^allow\ out\ to\ ([^[:space:]]+)\ port\ ([0-9]+)\ proto\ (tcp|udp)$ ]]; then
    ufw allow out to "${BASH_REMATCH[1]}" port "${BASH_REMATCH[2]}" proto "${BASH_REMATCH[3]}"
  fi
done <"$ROOT/deploy/ufw/user.rules"
if [[ -n "${AZURE_API_HOST:-}" ]]; then
  ufw allow out to "${AZURE_API_HOST}" port 443 proto tcp
fi
if [[ -n "${DNS_SERVERS:-}" ]]; then
  ufw allow out to "${DNS_SERVERS}" port 53 proto udp
fi
if [[ -n "${SIEM_HOST:-}" && -n "${SIEM_PORT:-}" ]]; then
  ufw allow out to "${SIEM_HOST}" port "${SIEM_PORT}" proto tcp
fi
ufw --force enable

if [[ ! -f /var/lib/local-ai-stack/certs/webui.key ]]; then
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout /var/lib/local-ai-stack/certs/webui.key \
    -out /var/lib/local-ai-stack/certs/webui.crt \
    -days 825 \
    -subj "/CN=webui.lan.internal"
  chmod 0600 /var/lib/local-ai-stack/certs/webui.key
fi

install -m 0644 "$ROOT/deploy/ssh/99-local-ai.conf" /etc/ssh/sshd_config.d/99-local-ai.conf
if [[ "${APPLY_SSH_HARDENING:-0}" == "1" ]]; then
  systemctl reload ssh || systemctl reload sshd
fi

install -m 0644 "$ROOT/deploy/systemd/local-ai-stack.service" /etc/systemd/system/local-ai-stack.service
install -m 0644 "$ROOT/deploy/systemd/local-ai-retention.service" /etc/systemd/system/local-ai-retention.service
install -m 0644 "$ROOT/deploy/systemd/local-ai-retention.timer" /etc/systemd/system/local-ai-retention.timer
install -m 0644 "$ROOT/deploy/systemd/cloudflared.service" /etc/systemd/system/cloudflared.service
systemctl daemon-reload
systemctl enable local-ai-stack.service
systemctl enable --now local-ai-retention.timer
systemctl disable --now cloudflared.service || true
systemctl enable systemd-timesyncd
systemctl enable auditd || true

echo "install complete; stack unit is enabled and cloudflared is disabled"
