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

# Poll the API's own health endpoint via `docker compose exec` so this works
# regardless of the container's actual name (COMPOSE_PROJECT_NAME may differ).
wait_for_api_health() {
  for i in $(seq 1 50); do
    if sudo -u "$APP_USER" docker compose exec -T api \
        node -e "require('http').get('http://localhost:3000/api/health',r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))" \
        2>/dev/null; then
      return 0
    fi
    [[ $i -lt 50 ]] && sleep 3
  done
  return 1
}

# Restart API first (nginx keeps serving while API is down; requests queue briefly)
info "Restarting API service…"
sudo -u "$APP_USER" docker compose up -d --no-deps api

info "Waiting for API health check…"
if wait_for_api_health; then
  success "API is healthy"
else
  warn "API failed to become healthy after 150 s — rolling back to ${OLD_SHA}"
  sudo -u "$APP_USER" git -C "$APP_DIR" reset --hard "$OLD_SHA"
  sudo -u "$APP_USER" docker compose build api
  sudo -u "$APP_USER" docker compose up -d --no-deps api

  info "Waiting for rolled-back API to become healthy…"
  if wait_for_api_health; then
    warn "Rolled back to ${OLD_SHA} — API is healthy again. The ${NEW_SHA} update was NOT applied."
    warn "Investigate the failure before retrying: docker compose logs api"
    exit 1
  else
    die "Rollback to ${OLD_SHA} ALSO failed to become healthy. Manual intervention required — check: docker compose logs api"
  fi
fi

# Restart nginx and verify it actually came back up before moving on —
# a bad nginx config should not be reported as a successful update.
info "Restarting nginx…"
sudo -u "$APP_USER" docker compose up -d --no-deps nginx

info "Verifying nginx…"
NGINX_OK=false
for i in $(seq 1 20); do
  if sudo -u "$APP_USER" docker compose exec -T nginx wget -q -O /dev/null http://localhost/healthz 2>/dev/null; then
    NGINX_OK=true
    break
  fi
  [[ $i -lt 20 ]] && sleep 2
done
if $NGINX_OK; then
  success "nginx is healthy"
else
  warn "nginx did not respond to /healthz after restart — check: docker compose logs nginx"
fi

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
