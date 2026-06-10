#!/usr/bin/env bash
# =============================================================================
# AESCSF v2 — Linode first-time server setup
#
# Run once on a fresh Ubuntu 22.04 / 24.04 Linode as root.
# Installs Docker, Caddy (HTTPS), UFW, creates an app user,
# clones the repo, collects configuration interactively, and
# starts the full stack.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/securelinksolutions/aescsfv2/main/deploy/setup.sh | bash
#   — or —
#   bash deploy/setup.sh
# =============================================================================
set -euo pipefail

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}▶${RESET}  $*"; }
success() { echo -e "${GREEN}✔${RESET}  $*"; }
warn()    { echo -e "${YELLOW}⚠${RESET}  $*"; }
die()     { echo -e "${RED}✘${RESET}  $*" >&2; exit 1; }
section() { echo -e "\n${BOLD}── $* ──────────────────────────────────────────${RESET}"; }

# ── Pre-flight ────────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || die "Run as root: sudo bash deploy/setup.sh"
[[ "$(uname -s)" == "Linux" ]] || die "This script targets Linux only."
command -v apt-get &>/dev/null || die "Requires an apt-based distro (Ubuntu/Debian)."

UBUNTU_VERSION=$(lsb_release -rs 2>/dev/null || echo "0")
info "Detected Ubuntu ${UBUNTU_VERSION}"

# ── Configuration ─────────────────────────────────────────────────────────────
APP_USER="aescsf"
APP_DIR="/opt/aescsf"
REPO_URL="https://github.com/securelinksolutions/aescsfv2.git"
BACKUP_DIR="/var/backups/aescsf"

section "Configuration"
echo -e "${BOLD}Answer the following — defaults shown in [brackets].${RESET}\n"

prompt() {
  local var="$1" msg="$2" default="${3:-}"
  read -r -p "$(echo -e "${CYAN}?${RESET} ${msg}${default:+ [${default}]}: ")" value
  printf -v "$var" '%s' "${value:-$default}"
}

prompt DOMAIN         "Your domain (e.g. aescsf.example.com)"
prompt CLIENT_ID      "Azure App (client) ID"
prompt TENANT_ID      "Azure Directory (tenant) ID"
prompt CLIENT_SECRET  "Azure Client Secret"
prompt ADMIN_OIDS     "Admin Object ID(s) — comma-separated (leave blank: first user becomes admin)" ""
prompt EMAIL_DOMAINS  "Allowed email domain(s) — * for any tenant user" "*"
prompt AUDIT_DAYS     "Audit log retention days" "365"

[[ -n "$DOMAIN" ]]        || die "Domain is required."
[[ -n "$CLIENT_ID" ]]     || die "Client ID is required."
[[ -n "$TENANT_ID" ]]     || die "Tenant ID is required."
[[ -n "$CLIENT_SECRET" ]] || die "Client Secret is required."

REDIRECT_URL="https://${DOMAIN}/oauth2/callback"
OIDC_ISSUER="https://login.microsoftonline.com/${TENANT_ID}/v2.0"
COOKIE_SECRET=$(openssl rand -hex 16)

echo ""
info "Domain:       ${DOMAIN}"
info "Redirect URL: ${REDIRECT_URL}"
info "OIDC Issuer:  ${OIDC_ISSUER}"
echo ""
read -r -p "$(echo -e "${YELLOW}Proceed with setup? [y/N]: ")" confirm
[[ "${confirm,,}" == "y" ]] || { warn "Aborted."; exit 0; }

# ── System update ─────────────────────────────────────────────────────────────
section "System Update"
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq
success "System packages updated"

# ── Docker ────────────────────────────────────────────────────────────────────
section "Docker"
if command -v docker &>/dev/null; then
  success "Docker already installed ($(docker --version | cut -d' ' -f3 | tr -d ','))"
else
  info "Installing Docker…"
  curl -fsSL https://get.docker.com | sh
  success "Docker installed"
fi

if ! docker compose version &>/dev/null; then
  info "Installing Docker Compose plugin…"
  apt-get install -y -qq docker-compose-plugin
fi
success "Docker Compose $(docker compose version --short) ready"

# ── Caddy ─────────────────────────────────────────────────────────────────────
section "Caddy (HTTPS)"
if ! command -v caddy &>/dev/null; then
  info "Installing Caddy…"
  apt-get install -y -qq debian-keyring debian-archive-keyring apt-transport-https
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
    | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
    | tee /etc/apt/sources.list.d/caddy-stable.list
  apt-get update -qq
  apt-get install -y -qq caddy
  success "Caddy installed"
else
  success "Caddy already installed ($(caddy version | head -1))"
fi

# ── Firewall ──────────────────────────────────────────────────────────────────
section "Firewall (UFW)"
apt-get install -y -qq ufw
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow http
ufw allow https
ufw --force enable
success "UFW enabled — SSH + HTTP + HTTPS open"

# ── App user ──────────────────────────────────────────────────────────────────
section "App User"
if id "$APP_USER" &>/dev/null; then
  success "User '${APP_USER}' already exists"
else
  useradd -m -s /bin/bash "$APP_USER"
  success "Created user '${APP_USER}'"
fi
usermod -aG docker "$APP_USER"
success "Added '${APP_USER}' to docker group"

# ── Repository ────────────────────────────────────────────────────────────────
section "Repository"
if [[ -d "$APP_DIR/.git" ]]; then
  warn "Repo already exists at ${APP_DIR} — pulling latest"
  sudo -u "$APP_USER" git -C "$APP_DIR" pull --ff-only
else
  info "Cloning into ${APP_DIR}…"
  git clone "$REPO_URL" "$APP_DIR"
  chown -R "$APP_USER:$APP_USER" "$APP_DIR"
fi
success "Repo ready at ${APP_DIR}"

# ── Environment file ──────────────────────────────────────────────────────────
section ".env"
ENV_FILE="${APP_DIR}/.env"

cat > "$ENV_FILE" <<EOF
# Generated by deploy/setup.sh on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# Edit manually or re-run setup.sh to regenerate.

# ── Entra ID ─────────────────────────────────────────────────────────────────
AESCSF_CLIENT_ID=${CLIENT_ID}
AESCSF_TENANT_ID=${TENANT_ID}
AESCSF_CLIENT_SECRET=${CLIENT_SECRET}

# ── oauth2-proxy ─────────────────────────────────────────────────────────────
OAUTH2_PROXY_REDIRECT_URL=${REDIRECT_URL}
OAUTH2_PROXY_OIDC_ISSUER_URL=${OIDC_ISSUER}
OAUTH2_PROXY_COOKIE_SECRET=${COOKIE_SECRET}
OAUTH2_PROXY_COOKIE_SECURE=true
OAUTH2_PROXY_EMAIL_DOMAINS=${EMAIL_DOMAINS}
OAUTH2_PROXY_WHITELIST_DOMAINS=${DOMAIN},login.microsoftonline.com

# ── RBAC ─────────────────────────────────────────────────────────────────────
AESCSF_ADMIN_OIDS=${ADMIN_OIDS}

# ── App ───────────────────────────────────────────────────────────────────────
AESCSF_STORAGE_MODE=api
AESCSF_AUDIT_RETENTION_DAYS=${AUDIT_DAYS}
ALLOWED_ORIGIN=https://${DOMAIN}

# ── Network (nginx binds to localhost; Caddy terminates TLS externally) ───────
HOST_BIND=127.0.0.1
HOST_PORT=80
EOF

chmod 600 "$ENV_FILE"
chown "$APP_USER:$APP_USER" "$ENV_FILE"
success ".env written to ${ENV_FILE}"

# ── Caddyfile ─────────────────────────────────────────────────────────────────
section "Caddyfile"
cat > /etc/caddy/Caddyfile <<EOF
# AESCSF v2 — Caddy reverse proxy
# Automatically obtains and renews a Let's Encrypt TLS certificate.

${DOMAIN} {
    # Proxy everything to the nginx container on localhost
    reverse_proxy localhost:80 {
        # Forward real client IP so audit logs capture it
        header_up X-Real-IP {remote_host}
        header_up X-Forwarded-For {remote_host}
        header_up X-Forwarded-Proto {scheme}
    }

    # Security headers
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        Referrer-Policy "strict-origin-when-cross-origin"
        -Server
    }

    # Compress responses
    encode zstd gzip

    log {
        output file /var/log/caddy/aescsf-access.log {
            roll_size 50mb
            roll_keep 7
        }
        format json
    }
}
EOF

mkdir -p /var/log/caddy
systemctl reload caddy || systemctl restart caddy
success "Caddyfile written and Caddy reloaded"

# ── Backup setup ──────────────────────────────────────────────────────────────
section "Automated Backups"
mkdir -p "$BACKUP_DIR"
chown "$APP_USER:$APP_USER" "$BACKUP_DIR"

cat > /usr/local/bin/aescsf-backup <<'BACKUP_SCRIPT'
#!/usr/bin/env bash
# Daily SQLite backup — keeps 30 days of snapshots
set -euo pipefail
BACKUP_DIR="/var/backups/aescsf"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
DEST="${BACKUP_DIR}/aescsf_${TIMESTAMP}.db"

# Copy from the named Docker volume using a temporary container
docker run --rm \
  -v aescsf_aescsf_data:/data:ro \
  -v "${BACKUP_DIR}:/backup" \
  alpine \
  sh -c "cp /data/aescsf.db /backup/aescsf_${TIMESTAMP}.db && echo 'Backup OK: aescsf_${TIMESTAMP}.db'"

# Prune backups older than 30 days
find "$BACKUP_DIR" -name "aescsf_*.db" -mtime +30 -delete
BACKUP_SCRIPT

chmod +x /usr/local/bin/aescsf-backup

# Add cron job at 02:00 daily
(crontab -l 2>/dev/null || true; echo "0 2 * * * /usr/local/bin/aescsf-backup >> /var/log/aescsf-backup.log 2>&1") | crontab -
success "Daily backup cron job set (02:00 UTC → ${BACKUP_DIR})"

# ── Unattended security upgrades ─────────────────────────────────────────────
section "Unattended Security Upgrades"
apt-get install -y -qq unattended-upgrades
cat > /etc/apt/apt.conf.d/50unattended-upgrades-aescsf <<'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF
success "Unattended security upgrades configured"

# ── Build and start ───────────────────────────────────────────────────────────
section "Build & Start"
info "Building Docker images (first build takes ~2 min)…"
cd "$APP_DIR"
sudo -u "$APP_USER" docker compose build --no-cache

info "Starting services…"
sudo -u "$APP_USER" docker compose up -d

# Wait for health checks
info "Waiting for API health check…"
for i in $(seq 1 30); do
  if sudo -u "$APP_USER" docker compose ps --format json | python3 -c "
import sys, json
data = sys.stdin.read()
try:
    services = [json.loads(l) for l in data.strip().splitlines() if l]
    api = next((s for s in services if 'api' in s.get('Service','')), None)
    sys.exit(0 if api and api.get('Health') == 'healthy' else 1)
except: sys.exit(1)
" 2>/dev/null; then
    success "API is healthy"
    break
  fi
  [[ $i -lt 30 ]] && sleep 3 || warn "API health check timed out — check logs: docker compose logs api"
done

# ── Summary ───────────────────────────────────────────────────────────────────
section "Done"
echo ""
echo -e "${GREEN}${BOLD}  AESCSF v2 is deployed!${RESET}"
echo ""
echo -e "  ${BOLD}URL:${RESET}      https://${DOMAIN}"
echo -e "  ${BOLD}App dir:${RESET}  ${APP_DIR}"
echo -e "  ${BOLD}Logs:${RESET}     cd ${APP_DIR} && docker compose logs -f"
echo -e "  ${BOLD}Update:${RESET}   bash ${APP_DIR}/deploy/update.sh"
echo -e "  ${BOLD}Backup:${RESET}   /usr/local/bin/aescsf-backup"
echo ""
warn "IMPORTANT: Add the redirect URI in Azure Portal before testing login:"
echo -e "  ${BOLD}${REDIRECT_URL}${RESET}"
echo ""
