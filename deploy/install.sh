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
  python3 "$ROOT/scripts/check_luks.py" --self-check
  bash "$ROOT/host/install.sh" --check
  exit 0
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "apply requires root" >&2
  exit 1
fi

# Steady state does not keep the cloudflared apt origin. Drop a leftover list
# before apt-get update so a re-apply does not dial pkg.cloudflare.com.
rm -f /etc/apt/sources.list.d/cloudflared.list
# Re-apply: the output filter is already loaded. Open install-only names on the
# apt proxy, then let apt and pip use it. First apply has no proxy yet.
if [[ -f /etc/apt/apt.conf.d/99local-ai-proxy ]] && systemctl is-active --quiet egress-proxy.service; then
  install -d -m 0755 /etc/systemd/system/egress-proxy.service.d
  printf '[Service]\nEnvironment=INSTALL_EGRESS=1\n' \
    > /etc/systemd/system/egress-proxy.service.d/install-egress.conf
  systemctl daemon-reload
  systemctl restart egress-proxy.service
  export http_proxy=http://127.0.0.1:8890
  export https_proxy=http://127.0.0.1:8890
  export HTTP_PROXY=http://127.0.0.1:8890
  export HTTPS_PROXY=http://127.0.0.1:8890
  export no_proxy=127.0.0.1,127.0.0.2,localhost
  export NO_PROXY=127.0.0.1,127.0.0.2,localhost
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y cryptsetup
bash "$ROOT/host/luks-data.sh" --apply
python3 "$ROOT/scripts/check_luks.py" --target /var/lib/local-ai-stack
bash "$ROOT/host/install.sh" --apply --skip-ufw
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
apt-get install -y caddy
if dpkg -s cloudflared >/dev/null 2>&1; then
  apt-get remove -y cloudflared
fi
rm -f /etc/apt/sources.list.d/cloudflared.list /usr/share/keyrings/cloudflare-main.gpg
systemctl disable --now cloudflared.service || true
rm -f /etc/systemd/system/cloudflared.service
rm -rf /etc/cloudflared

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
create_user egress-proxy /var/lib/local-ai-stack/egress-proxy

install -d -m 0755 \
  /opt/local-ai-stack \
  /opt/presidio-analyzer \
  /opt/presidio-anonymizer \
  /opt/litellm \
  /opt/policy-gateway \
  /opt/open-webui \
  /var/lib/local-ai-stack \
  /var/lib/local-ai-stack/backups \
  /var/lib/local-ai-stack/certs

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
cp -a "$ROOT/scripts/retire_bootstrap_admin.py" /opt/local-ai-stack/scripts/retire_bootstrap_admin.py
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
microsoft_client_id="$(awk -F= '$1=="MICROSOFT_CLIENT_ID" { print $2 }' /etc/open-webui/config.env)"
if [[ "$microsoft_client_id" == "00000000-0000-0000-0000-000000000000" ]]; then
  echo "refusing zero-GUID MICROSOFT_CLIENT_ID" >&2
  exit 1
fi

if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  # Re-running apply on a locked host needs pip and the model hosts, then drops them.
  INSTALL_EGRESS=1 python3 "$ROOT/scripts/egress_owners.py" --apply-ufw --dest "$ROOT/deploy/egress-destinations.yaml"
fi

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

bash "$ROOT/host/secrets/populate.sh"
# One pass for the Anthropic key. Stop LiteLLM before the file changes so a
# running process cannot keep LoadCredential bytes after the file is removed.
baa_stamp=/var/lib/local-ai-stack/litellm/baa-switch
baa_previous=false
if [[ -f "$baa_stamp" ]]; then
  baa_previous="$(<"$baa_stamp")"
fi
baa_current=false
if [[ "${ANTHROPIC_BAA_ENABLED:-false}" == "true" ]]; then
  baa_current=true
fi
if systemctl cat litellm.service >/dev/null 2>&1; then
  systemctl stop litellm.service
fi
if [[ "$baa_current" == "true" ]]; then
  bash "$ROOT/deploy/write-secret.sh" /etc/litellm/anthropic_api_key ANTHROPIC_API_KEY
else
  rm -f /etc/litellm/anthropic_api_key
fi
rm -f /etc/cloudflared/credentials.json

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
install -m 0644 "$ROOT/deploy/systemd/local-ai-store-purge.service" /etc/systemd/system/local-ai-store-purge.service
install -m 0644 "$ROOT/deploy/systemd/local-ai-store-purge.timer" /etc/systemd/system/local-ai-store-purge.timer
install -m 0644 "$ROOT/deploy/systemd/local-ai-retire-bootstrap.service" /etc/systemd/system/local-ai-retire-bootstrap.service
install -m 0644 "$ROOT/deploy/systemd/local-ai-retire-bootstrap.timer" /etc/systemd/system/local-ai-retire-bootstrap.timer
install -d -m 0755 /etc/systemd/system/caddy.service.d /etc/systemd/system/postgresql@.service.d
install -m 0644 "$ROOT/deploy/systemd/caddy.service.d.conf" /etc/systemd/system/caddy.service.d/10-hardening.conf
install -m 0644 "$ROOT/deploy/systemd/postgresql.service.d.conf" /etc/systemd/system/postgresql@.service.d/10-hardening.conf
install -m 0644 "$ROOT/deploy/Caddyfile" /etc/caddy/Caddyfile
install -m 0644 "$ROOT/deploy/ssh/99-local-ai.conf" /etc/ssh/sshd_config.d/99-local-ai.conf
install -d -m 0755 /etc/systemd/journald.conf.d
install -m 0644 "$ROOT/deploy/journald/local-ai.conf" /etc/systemd/journald.conf.d/local-ai.conf
install -d -m 0755 /etc/systemd/timesyncd.conf.d
install -m 0644 "$ROOT/deploy/systemd/timesyncd.conf.d/local-ai.conf" /etc/systemd/timesyncd.conf.d/local-ai.conf
install -d -m 0755 /usr/share/local-ai-stack
install -m 0644 "$ROOT/deploy/wireguard/wg0.conf.example" /usr/share/local-ai-stack/wg0.conf.example

bind_ip="${VPN_BIND_IP:-127.0.0.1}"
wildcard="$(printf '%s.%s.%s.%s' 0 0 0 0)"
if [[ "$bind_ip" == "::" || "$bind_ip" == "::0" || "$bind_ip" == "$wildcard" ]] || [[ ! "$bind_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "VPN_BIND_IP must be a loopback or VPN address" >&2
  exit 1
fi
printf '[Service]\nEnvironment=VPN_BIND_IP=%s\n' "$bind_ip" > /etc/systemd/system/caddy.service.d/20-bind.conf
if [[ -n "${VPN_SSH_CIDR:-}" ]]; then
  world="$(printf '%s.%s.%s.%s/0' 0 0 0 0)"
  if [[ "$VPN_SSH_CIDR" == "$world" || "$VPN_SSH_CIDR" == "any" || "$VPN_SSH_CIDR" == "::/0" ]] \
    || [[ ! "$VPN_SSH_CIDR" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$ ]]; then
    echo "VPN_SSH_CIDR must be an IPv4 prefix" >&2
    exit 1
  fi
  # Peer filter. systemd does not accept hostnames here; the prefix is an address.
  printf '[Service]\nIPAddressAllow=%s\n' "$VPN_SSH_CIDR" > /etc/systemd/system/caddy.service.d/30-vpn-clients.conf
fi

if [[ -n "${AZURE_API_HOST:-}" ]]; then
  if ! PYTHONPATH="$ROOT" python3 -c 'import os,sys; from stack.egress import azure_host_ok; sys.exit(0 if azure_host_ok(os.environ["AZURE_API_HOST"]) else 1)'; then
    echo "AZURE_API_HOST must be one label, include a US region, and end in .openai.azure.com" >&2
    exit 1
  fi
  rm -f /etc/systemd/system/litellm.service.d/azure.conf
fi

install -m 0644 "$ROOT/deploy/sysctl/99-local-ai.conf" /etc/sysctl.d/99-local-ai.conf
sysctl --system >/dev/null

bash "$ROOT/host/ufw.sh"
python3 "$ROOT/scripts/check_luks.py" --target /var/lib/local-ai-stack

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

bash "$ROOT/deploy/litellm-baa-dropin.sh" "$baa_current" \
  /etc/systemd/system/litellm.service.d \
  "$ROOT/deploy/systemd/litellm.service.d/10-anthropic.conf"
install -d -m 0755 /etc/local-ai-stack
{
  printf 'ANTHROPIC_BAA_ENABLED=%s\n' "$baa_current"
  if [[ -n "${AZURE_API_HOST:-}" ]]; then
    printf 'AZURE_API_HOST=%s\n' "$AZURE_API_HOST"
  fi
} > /etc/local-ai-stack/egress.env
chmod 0644 /etc/local-ai-stack/egress.env
install -m 0755 "$ROOT/deploy/egress-refresh.sh" /usr/local/sbin/local-ai-egress-refresh
sed "s|@LOCAL_AI_ROOT@|$ROOT|g" "$ROOT/deploy/systemd/local-ai-egress-refresh.service" \
  > /etc/systemd/system/local-ai-egress-refresh.service
install -m 0644 "$ROOT/deploy/systemd/local-ai-egress-refresh.timer" /etc/systemd/system/local-ai-egress-refresh.timer
sed "s|@LOCAL_AI_ROOT@|$ROOT|g" "$ROOT/deploy/systemd/local-ai-egress-nft.service" \
  > /etc/systemd/system/local-ai-egress-nft.service
rm -f /etc/systemd/system/egress-proxy.service.d/install-egress.conf
install -d -m 0750 -o egress-proxy -g egress-proxy /var/lib/local-ai-stack/egress-proxy
install -m 0755 "$ROOT/deploy/egress-proxy.py" /usr/local/sbin/local-ai-egress-proxy
install -m 0644 "$ROOT/deploy/egress-destinations.yaml" /etc/local-ai-stack/egress-destinations.yaml
install -m 0644 "$ROOT/deploy/systemd/egress-proxy.service" /etc/systemd/system/egress-proxy.service
python3 "$ROOT/scripts/egress_nft.py" | nft -f -
systemctl daemon-reload
systemctl enable postgresql.service
systemctl enable presidio-analyzer.service
systemctl enable presidio-anonymizer.service
systemctl enable litellm.service
systemctl enable egress-proxy.service
systemctl enable policy-gateway.service
systemctl enable open-webui.service
systemctl enable caddy.service
systemctl enable local-ai-stack.target
systemctl enable --now local-ai-retention.timer
systemctl enable --now local-ai-store-purge.timer
systemctl enable --now local-ai-retire-bootstrap.timer
if [[ -f /etc/wireguard/wg0.conf ]]; then
  systemctl enable wg-quick@wg0.service
else
  systemctl disable wg-quick@wg0.service || true
fi
systemctl enable systemd-timesyncd
systemctl restart systemd-timesyncd || true
systemctl restart systemd-journald || true
systemctl enable auditd || true
rm -f /etc/systemd/system/network-pre.target.wants/local-ai-egress-nft.service
systemctl enable local-ai-egress-nft.service
systemctl enable --now local-ai-egress-refresh.timer

systemctl restart egress-proxy.service
systemctl start litellm.service
# LiteLLM :4000 rejects the openwebui uid, so this probe stays root.
litellm_up=0
for _ in $(seq 1 60); do
  if curl -fsS --max-time 2 http://127.0.0.2:4000/health/liveliness >/dev/null; then
    litellm_up=1
    break
  fi
  sleep 1
done
if [[ "$litellm_up" -ne 1 ]]; then
  echo "LiteLLM did not come up; virtual key was not scoped" >&2
  exit 1
fi
if [[ "$baa_previous" != "$baa_current" ]]; then
  export SCOPE_VIRTUAL_KEY_FORCE=1
fi
LITELLM_MASTER_KEY_FILE=/etc/litellm/litellm_master_key \
  VIRTUAL_KEY_DEST=/etc/policy-gateway/litellm_virtual_key \
  LITELLM_BASE_URL=http://127.0.0.2:4000 \
  ANTHROPIC_BAA_ENABLED="$baa_current" \
  python3 "$ROOT/scripts/scope_virtual_key.py"
unset SCOPE_VIRTUAL_KEY_FORCE
install -d -m 0755 "$(dirname "$baa_stamp")"
printf '%s\n' "$baa_current" > "$baa_stamp"
chmod 0644 "$baa_stamp"
rm -f /etc/apt/sources.list.d/cloudflared.list
install -m 0644 "$ROOT/deploy/apt/99local-ai-proxy" /etc/apt/apt.conf.d/99local-ai-proxy

systemctl restart policy-gateway.service
# :8088 accepts only the openwebui uid, so the probe cannot run as root.
gateway_up=0
for _ in $(seq 1 60); do
  if bash "$ROOT/deploy/health-check.sh" gateway; then
    gateway_up=1
    break
  fi
  sleep 1
done
if [[ "$gateway_up" -ne 1 ]]; then
  echo "policy gateway health check failed" >&2
  exit 1
fi

python3 "$ROOT/scripts/retire_bootstrap_admin.py" \
  --db /var/lib/local-ai-stack/webui/webui.db \
  --password-file /etc/open-webui/webui_admin_password
bash "$ROOT/deploy/check-password-login.sh" --live --allow-down

echo "install complete; native units are enabled"
