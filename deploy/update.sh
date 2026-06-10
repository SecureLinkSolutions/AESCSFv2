#!/usr/bin/env bash
# =============================================================================
# AESCSF v2 — Zero-downtime update script
#
# Run on the server as root (or as the aescsf user with sudo for docker).
# Pulls the latest code, rebuilds images, and restarts services with no
# prolonged downtime — nginx stays up while the API rebuilds.
#
# Usage:
#   bash /opt/aescsf/deploy/update.sh
#   — or as root —
#   bash /opt/aescsf/deploy/update.sh --skip-backup
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}▶${RESET}  $*"; }
success() { echo -e "${GREEN}✔${RESET}  $*"; }
warn()    { echo -e "${YELLOW}⚠${RESET}  $*"; }
die()     { echo -e "${RED}✘${RESET}  $*" >&2; exit 1; }
section() { echo -e "\n${BOLD}── $* ──────────────────────────────────────────${RESET}"; }

APP_DIR="/opt/aescsf"
APP_USER="aescsf"
SKIP_BACKUP=false

for arg in "$@"; do
  [[ "$arg" == "--skip-backup" ]] && SKIP_BACKUP=true
done

[[ -d "$APP_DIR" ]] || die "App directory ${APP_DIR} not found. Run setup.sh first."
command -v docker &>/dev/null || die "Docker not found. Run setup.sh first."

# ── Pre-update backup ─────────────────────────────────────────────────────────
section "Pre-update Backup"
if $SKIP_BACKUP; then
  warn "Skipping backup (--skip-backup flag set)"
elif command -v /usr/local/bin/aescsf-backup &>/dev/null; then
  info "Taking snapshot before update…"
  /usr/local/bin/aescsf-backup && success "Backup complete"
else
  warn "Backup script not found — skipping. Run setup.sh to install it."
fi

# ── Pull latest code ──────────────────────────────────────────────────────────
section "Pull Latest Code"
OLD_SHA=$(sudo -u "$APP_USER" git -C "$APP_DIR" rev-parse --short HEAD 2>/dev/null || echo "unknown")
info "Current commit: ${OLD_SHA}"

sudo -u "$APP_USER" git -C "$APP_DIR" fetch --prune origin
sudo -u "$APP_USER" git -C "$APP_DIR" pull --ff-only

NEW_SHA=$(sudo -u "$APP_USER" git -C "$APP_DIR" rev-parse --short HEAD)
if [[ "$OLD_SHA" == "$NEW_SHA" ]]; then
  warn "Already up to date (${NEW_SHA}). Nothing to rebuild."
  exit 0
fi
success "Updated ${OLD_SHA} → ${NEW_SHA}"

# Show what changed
echo ""
info "Changes:"
sudo -u "$APP_USER" git -C "$APP_DIR" log --oneline "${OLD_SHA}..${NEW_SHA}" | sed 's/^/    /'
echo ""

# ── Rebuild images ────────────────────────────────────────────────────────────
section "Rebuild Images"
cd "$APP_DIR"

info "Building updated images…"
sudo -u "$APP_USER" docker compose build

success "Images built"

# ── Rolling restart ───────────────────────────────────────────────────────────
section "Rolling Restart"

# Restart API first (nginx keeps serving while API is down; requests queue briefly)
info "Restarting API service…"
sudo -u "$APP_USER" docker compose up -d --no-deps api

# Wait for API health — poll the health endpoint directly
info "Waiting for API health check…"
HEALTHY=false
for i in $(seq 1 50); do
  if docker exec aescsf-api-1 \
      node -e "require('http').get('http://localhost:3000/api/health',r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))" \
      2>/dev/null; then
    HEALTHY=true
    success "API is healthy"
    break
  fi
  [[ $i -lt 50 ]] && sleep 3
done

if ! $HEALTHY; then
  die "API failed to become healthy after 150 s. Check logs: docker compose logs api"
fi

# Restart nginx and oauth2-proxy (very fast — no data)
info "Restarting nginx…"
sudo -u "$APP_USER" docker compose up -d --no-deps nginx

info "Restarting oauth2-proxy…"
sudo -u "$APP_USER" docker compose up -d --no-deps oauth2-proxy

success "All services restarted"

# ── Prune old images ──────────────────────────────────────────────────────────
section "Cleanup"
info "Removing unused Docker images…"
docker image prune -f --filter "until=24h" >/dev/null 2>&1 || true
success "Pruned dangling images"

# ── Summary ───────────────────────────────────────────────────────────────────
section "Done"
echo ""
echo -e "${GREEN}${BOLD}  Update complete!${RESET}"
echo ""
echo -e "  ${BOLD}Previous:${RESET} ${OLD_SHA}"
echo -e "  ${BOLD}Current:${RESET}  ${NEW_SHA}"
echo ""
echo -e "  ${BOLD}Logs:${RESET}     cd ${APP_DIR} && docker compose logs -f"
echo ""
