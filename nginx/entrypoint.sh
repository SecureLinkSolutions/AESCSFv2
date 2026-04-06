#!/bin/sh
# Generates /usr/share/nginx/html/config.js from environment variables,
# then hands off to the default CMD (nginx).
# clientId and tenantId are no longer needed here — auth is handled by oauth2-proxy.

CONFIG_FILE="/usr/share/nginx/html/config.js"
STORAGE_MODE="${AESCSF_STORAGE_MODE:-api}"

cat > "$CONFIG_FILE" <<EOF
/* Auto-generated at container start — do not edit manually */
window.__AESCSF_CONFIG__ = {
  storageMode:       "${STORAGE_MODE}",
  apiBaseUrl:        "/api",
  apiAssessmentPath: "/assessment"
};
EOF

echo "[AESCSF] config.js written (storageMode=${STORAGE_MODE})"

exec "$@"
