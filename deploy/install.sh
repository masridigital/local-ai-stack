#!/usr/bin/env bash
# Idempotent native Ubuntu Server LTS install. No Docker.
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
  python3 \
  python3-venv \
  python3-dev \
  build-essential \
  ca-certificates \
  curl \
  gnupg \
  ufw \
  unattended-upgrades \
  apt-listchanges \
  auditd \
  apparmor \
  openssl \
  restic \
  postgresql \
  postgresql-contrib \
  wireguard

bash "$ROOT/deploy/apt-repos.sh"
apt-get update
apt-get install -y caddy cloudflared

create_user() {
  local name="$1"
  local home="$2"
  if ! id "$name" >/dev/null 2>&1; then
    useradd --system --home-dir "$home" --shell /usr/sbin/nologin "$name"
  fi
}

create_user presidio-analyzer /var/lib/local-ai-stack/presidio-analyzer
create_user presidio-anonymizer /var/lib/local-ai-stack/presidio-anonymizer
create_user litellm /var/lib/local-ai-stack/litellm
create_user policy-gateway /var/lib/local-ai-stack/policy-gateway
create_user openwebui /var/lib/local-ai-stack/webui

install -d -m 0755 \
  /opt/local-ai-stack \
  /opt/presidio-analyzer \
  /opt/presidio-anonymizer \
  /opt/litellm \
  /opt/policy-gateway \
  /opt/open-webui \
  /var/lib/local-ai-stack \
  /var/lib/local-ai-stack/backups \
  /var/lib/local-ai-stack/certs \
  /etc/cloudflared

install -d -m 0700 -o presidio-analyzer -g presidio-analyzer /var/lib/local-ai-stack/presidio-analyzer
install -d -m 0700 -o presidio-anonymizer -g presidio-anonymizer /var/lib/local-ai-stack/presidio-anonymizer
install -d -m 0700 -o litellm -g litellm /var/lib/local-ai-stack/litellm
install -d -m 0700 -o policy-gateway -g policy-gateway /var/lib/local-ai-stack/policy-gateway
install -d -m 0700 -o openwebui -g openwebui /var/lib/local-ai-stack/webui
install -d -m 0700 -o openwebui -g openwebui /var/lib/local-ai-stack/webui/hf
install -d -m 0700 -o openwebui -g openwebui /var/lib/local-ai-stack/webui/st
install -d -m 0700 /etc/presidio-analyzer /etc/presidio-anonymizer /etc/litellm /etc/policy-gateway /etc/open-webui /etc/postgres

install -d -m 0755 /opt/local-ai-stack/scripts /opt/local-ai-stack/postgres /opt/local-ai-stack/deploy
cp -a "$ROOT/scripts/ensure_postgres.py" /opt/local-ai-stack/scripts/ensure_postgres.py
cp -a "$ROOT/postgres/init" /opt/local-ai-stack/postgres/init
rm -rf /opt/policy-gateway/stack /opt/policy-gateway/litellm /opt/policy-gateway/presidio
cp -a "$ROOT/stack" /opt/policy-gateway/stack
cp -a "$ROOT/litellm" /opt/policy-gateway/litellm
cp -a "$ROOT/presidio" /opt/policy-gateway/presidio
rm -rf /opt/presidio-analyzer/server /opt/presidio-anonymizer/server
cp -a "$ROOT/presidio/server/analyzer" /opt/presidio-analyzer/server
cp -a "$ROOT/presidio/server/anonymizer" /opt/presidio-anonymizer/server
install -d -m 0755 /opt/litellm/presidio
install -m 0644 "$ROOT/litellm/config.yaml" /opt/litellm/config.yaml
install -m 0644 "$ROOT/presidio/recognizers.json" /opt/litellm/presidio/recognizers.json
install -m 0755 "$ROOT/deploy/litellm-run.sh" /opt/litellm/litellm-run.sh
install -m 0755 "$ROOT/deploy/open-webui-run.sh" /opt/open-webui/open-webui-run.sh
chown -R root:root /opt/presidio-analyzer /opt/presidio-anonymizer /opt/litellm /opt/policy-gateway /opt/open-webui

install_config() {
  local src="$1"
  local dest="$2"
  if [[ ! -f "$dest" ]]; then
    install -m 0600 -o root -g root "$src" "$dest"
  fi
}

install_config "$ROOT/deploy/env/litellm.env" /etc/litellm/config.env
install_config "$ROOT/deploy/env/policy-gateway.env" /etc/policy-gateway/config.env
install_config "$ROOT/deploy/env/open-webui.env" /etc/open-webui/config.env

install_venv() {
  local dest="$1"
  shift
  if [[ ! -x "${dest}/venv/bin/pip" ]]; then
    python3 -m venv "${dest}/venv"
  fi
  local stamp digest req
  digest="$( (cd "$ROOT" && sha256sum "$@") | sha256sum | awk '{ print $1 }')"
  stamp="${dest}/venv/.requirements-sha256"
  if [[ -f "$stamp" ]] && [[ "$(<"$stamp")" == "$digest" ]]; then
    return 0
  fi
  for req in "$@"; do
    "${dest}/venv/bin/pip" install --require-hashes -r "${ROOT}/${req}"
  done
  printf '%s\n' "$digest" >"$stamp"
  chown -R root:root "${dest}/venv"
}

install_venv /opt/presidio-analyzer requirements/presidio-analyzer.txt requirements/spacy-model.txt
install_venv /opt/presidio-anonymizer requirements/presidio-anonymizer.txt
install_venv /opt/litellm requirements/litellm.txt
install_venv /opt/policy-gateway requirements/policy-gateway.txt
install_venv /opt/open-webui requirements/open-webui.txt

if [[ "${ALLOW_EMBEDDING_DOWNLOAD:-1}" == "1" ]] && [[ ! -d /var/lib/local-ai-stack/webui/hf/hub ]]; then
  HF_HOME=/var/lib/local-ai-stack/webui/hf \
    SENTENCE_TRANSFORMERS_HOME=/var/lib/local-ai-stack/webui/st \
    /opt/open-webui/venv/bin/python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2')"
  chown -R openwebui:openwebui /var/lib/local-ai-stack/webui
fi

bash "$ROOT/deploy/write-secret.sh" /etc/postgres/postgres_password POSTGRES_PASSWORD
bash "$ROOT/deploy/write-secret.sh" /etc/litellm/litellm_master_key LITELLM_MASTER_KEY
bash "$ROOT/deploy/write-secret.sh" /etc/litellm/anthropic_api_key ANTHROPIC_API_KEY
bash "$ROOT/deploy/write-secret.sh" /etc/litellm/azure_client_secret AZURE_CLIENT_SECRET
bash "$ROOT/deploy/write-secret.sh" /etc/litellm/database_url DATABASE_URL
bash "$ROOT/deploy/write-secret.sh" /etc/policy-gateway/litellm_virtual_key LITELLM_VIRTUAL_KEY
bash "$ROOT/deploy/write-secret.sh" /etc/policy-gateway/audit_database_url AUDIT_DATABASE_URL
bash "$ROOT/deploy/write-secret.sh" /etc/open-webui/webui_secret_key WEBUI_SECRET_KEY
bash "$ROOT/deploy/write-secret.sh" /etc/open-webui/microsoft_client_secret MICROSOFT_CLIENT_SECRET
bash "$ROOT/deploy/write-secret.sh" /etc/open-webui/litellm_virtual_key LITELLM_VIRTUAL_KEY
bash "$ROOT/deploy/write-secret.sh" /etc/cloudflared/credentials.json CLOUDFLARED_CREDENTIALS_JSON

bind_postgres_data() {
  local dest="/var/lib/local-ai-stack/postgres"
  local stock="/var/lib/postgresql"
  install -d -m 0700 "$dest"
  chown postgres:postgres "$dest"
  if grep -qF "$dest $stock none bind" /etc/fstab; then
    if ! mountpoint -q "$stock"; then
      mount --bind "$dest" "$stock"
    fi
    return 0
  fi
  systemctl stop postgresql || true
  if [[ -z "$(ls -A "$dest")" ]] && [[ -n "$(ls -A "$stock" 2>/dev/null || true)" ]]; then
    cp -a "${stock}/." "$dest/"
  fi
  printf '%s\n' "$dest $stock none bind 0 0" >> /etc/fstab
  mount --bind "$dest" "$stock"
}

bind_postgres_data
pg_ver="$(pg_lsclusters --no-header | awk 'NR==1 { print $1 }')"
install -d -m 0755 "/etc/postgresql/${pg_ver}/main/conf.d"
printf "%s\n" "listen_addresses = '127.0.0.1'" > "/etc/postgresql/${pg_ver}/main/conf.d/local-ai.conf"
systemctl enable postgresql
systemctl restart postgresql
if [[ -f /etc/postgres/postgres_password ]]; then
  POSTGRES_PASSWORD="$(< /etc/postgres/postgres_password)"
  export POSTGRES_PASSWORD
  export AUDIT_SCHEMA=/opt/local-ai-stack/postgres/init/001-audit.sql
  sudo --preserve-env=POSTGRES_PASSWORD,AUDIT_SCHEMA -u postgres \
    /opt/policy-gateway/venv/bin/python /opt/local-ai-stack/scripts/ensure_postgres.py
  unset POSTGRES_PASSWORD AUDIT_SCHEMA
fi

install -m 0644 "$ROOT/deploy/systemd/presidio-analyzer.service" /etc/systemd/system/presidio-analyzer.service
install -m 0644 "$ROOT/deploy/systemd/presidio-anonymizer.service" /etc/systemd/system/presidio-anonymizer.service
install -m 0644 "$ROOT/deploy/systemd/litellm.service" /etc/systemd/system/litellm.service
install -m 0644 "$ROOT/deploy/systemd/policy-gateway.service" /etc/systemd/system/policy-gateway.service
install -m 0644 "$ROOT/deploy/systemd/open-webui.service" /etc/systemd/system/open-webui.service
install -m 0644 "$ROOT/deploy/systemd/local-ai-stack.target" /etc/systemd/system/local-ai-stack.target
install -m 0644 "$ROOT/deploy/systemd/local-ai-retention.service" /etc/systemd/system/local-ai-retention.service
install -m 0644 "$ROOT/deploy/systemd/local-ai-retention.timer" /etc/systemd/system/local-ai-retention.timer
install -m 0644 "$ROOT/deploy/systemd/cloudflared.service" /etc/systemd/system/cloudflared.service
install -d -m 0755 /etc/systemd/system/caddy.service.d /etc/systemd/system/postgresql@.service.d
install -m 0644 "$ROOT/deploy/systemd/caddy.service.d.conf" /etc/systemd/system/caddy.service.d/10-hardening.conf
install -m 0644 "$ROOT/deploy/systemd/postgresql.service.d.conf" /etc/systemd/system/postgresql@.service.d/10-hardening.conf
install -m 0644 "$ROOT/deploy/Caddyfile" /etc/caddy/Caddyfile
install -m 0644 "$ROOT/deploy/cloudflared/config.yml" /etc/cloudflared/config.yml
install -m 0644 "$ROOT/deploy/ssh/99-local-ai.conf" /etc/ssh/sshd_config.d/99-local-ai.conf
install -d -m 0755 /etc/systemd/journald.conf.d
install -m 0644 "$ROOT/deploy/journald/local-ai.conf" /etc/systemd/journald.conf.d/local-ai.conf
install -d -m 0755 /usr/share/local-ai-stack
install -m 0644 "$ROOT/deploy/wireguard/wg0.conf.example" /usr/share/local-ai-stack/wg0.conf.example

bind_ip="${VPN_BIND_IP:-127.0.0.1}"
wildcard="$(printf '%s.%s.%s.%s' 0 0 0 0)"
if [[ "$bind_ip" == "$wildcard" ]] || [[ ! "$bind_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "VPN_BIND_IP must be a loopback or VPN address" >&2
  exit 1
fi
printf '[Service]\nEnvironment=VPN_BIND_IP=%s\n' "$bind_ip" > /etc/systemd/system/caddy.service.d/20-bind.conf

if [[ -n "${AZURE_API_HOST:-}" ]]; then
  if [[ ! "$AZURE_API_HOST" =~ ^[A-Za-z0-9.-]+\.openai\.azure\.com$ ]]; then
    echo "AZURE_API_HOST must be a hostname ending in .openai.azure.com" >&2
    exit 1
  fi
  install -d -m 0755 /etc/systemd/system/litellm.service.d
  printf '[Service]\nIPAddressAllow=%s\n' "$AZURE_API_HOST" > /etc/systemd/system/litellm.service.d/azure.conf
fi

install -m 0644 "$ROOT/deploy/sysctl/99-local-ai.conf" /etc/sysctl.d/99-local-ai.conf
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

if [[ -f /etc/docker/daemon.json ]] && grep -q 'tcp://' /etc/docker/daemon.json; then
  echo "refusing to leave a Docker TCP socket configured" >&2
  exit 1
fi

ufw default deny incoming
ufw default deny outgoing
ufw allow in on lo
ufw allow out on lo
if [[ -n "${VPN_SSH_CIDR:-}" ]]; then
  ufw allow from "${VPN_SSH_CIDR}" to any port 22 proto tcp
  ufw allow from "${VPN_SSH_CIDR}" to any port 443 proto tcp
fi
if [[ -n "${WIREGUARD_LISTEN_PORT:-}" ]]; then
  ufw allow "${WIREGUARD_LISTEN_PORT}/udp"
fi
python3 "$ROOT/scripts/egress_owners.py" --apply-ufw --dest "$ROOT/deploy/egress-destinations.yaml"
ufw --force enable

if [[ ! -f /var/lib/local-ai-stack/certs/webui.key ]]; then
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout /var/lib/local-ai-stack/certs/webui.key \
    -out /var/lib/local-ai-stack/certs/webui.crt \
    -days 825 \
    -subj "/CN=webui.lan.internal"
  chmod 0600 /var/lib/local-ai-stack/certs/webui.key
fi

if [[ "${APPLY_SSH_HARDENING:-0}" == "1" ]]; then
  systemctl reload ssh || systemctl reload sshd
fi

systemctl daemon-reload
systemctl enable postgresql.service
systemctl enable presidio-analyzer.service
systemctl enable presidio-anonymizer.service
systemctl enable litellm.service
systemctl enable policy-gateway.service
systemctl enable open-webui.service
systemctl enable caddy.service
systemctl enable local-ai-stack.target
systemctl enable --now local-ai-retention.timer
systemctl disable --now cloudflared.service || true
if [[ -f /etc/wireguard/wg0.conf ]]; then
  systemctl enable wg-quick@wg0.service
else
  systemctl disable wg-quick@wg0.service || true
fi
systemctl enable systemd-timesyncd
systemctl restart systemd-journald || true
systemctl enable auditd || true

echo "install complete; native units are enabled and cloudflared is disabled"
