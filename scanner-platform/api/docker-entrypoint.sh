#!/bin/sh
set -e
# Apply database migrations before starting the API.
alembic upgrade head
exec "$@"
