#!/bin/sh
set -e
# Apply database migrations before starting. The verifier skips this and
# waits for the api's healthcheck instead, so only one container migrates.
if [ "${RUN_MIGRATIONS:-true}" = "true" ]; then
  alembic upgrade head
fi
exec "$@"
