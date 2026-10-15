#!/usr/bin/env bash
# Verifies the stack exposes nothing outside the Tailscale interface.
# Run on the host after `docker compose up -d`. Exits non-zero on any problem.
set -euo pipefail
cd "$(dirname "$0")/.."

fail=0
ts_ip=$(grep -E '^TAILSCALE_IP=' .env | cut -d= -f2)
[ -n "$ts_ip" ] || { echo "FAIL: TAILSCALE_IP not set in .env"; exit 1; }

echo "== Published container ports (expect only caddy on $ts_ip:443)"
while read -r service ports; do
  [ -z "$service" ] && continue
  IFS=',' read -ra entries <<< "$ports"
  for entry in "${entries[@]}"; do
    entry=$(echo "$entry" | xargs)
    case "$entry" in *"->"*) ;; *) continue ;; esac
    if [ "$service" = "caddy" ] && [ "$entry" = "$ts_ip:443->443/tcp" ]; then
      echo "  ok   $service $entry"
    else
      echo "  FAIL $service $entry"; fail=1
    fi
  done
done < <(docker compose ps --format '{{.Service}} {{.Ports}}')

echo "== Host TCP listeners on wildcard addresses"
if command -v ss >/dev/null; then
  # sshd on 0.0.0.0:22 is expected until M6 locks SSH to Tailscale.
  wild=$(ss -Hltn | awk '{print $4}' | grep -E '^(0\.0\.0\.0|\*|\[::\]):' | grep -vE ':22$' || true)
  if [ -n "$wild" ]; then echo "$wild" | sed 's/^/  /'; echo "  WARN: review the listeners above"; fi
else
  echo "  ss not installed; skipped"
fi

echo "== UFW"
if command -v ufw >/dev/null; then sudo ufw status verbose | sed 's/^/  /'; else echo "  ufw not installed"; fi

[ "$fail" -eq 0 ] && echo "OK: only Caddy is published, on $ts_ip:443" || exit 1
