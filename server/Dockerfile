FROM node:20-alpine

WORKDIR /app

# Install native build tools needed by better-sqlite3
RUN apk add --no-cache python3 make g++

# Create a non-root user for least-privilege execution
RUN addgroup -S aescsf && adduser -S aescsf -G aescsf

COPY package.json ./
RUN npm install --omit=dev

COPY server.js ./

# Create the data directory with correct ownership before declaring the volume.
# For new installs Docker will copy this directory (with its ownership) into
# the named volume on first mount.
# NOTE: If upgrading from a previous release that ran as root, run:
#   docker compose run --rm --user root api chown -R aescsf:aescsf /data
RUN mkdir -p /data && chown aescsf:aescsf /data

# Data volume — SQLite database and uploaded files live here
VOLUME ["/data"]

USER aescsf

EXPOSE 3000

CMD ["node", "server.js"]
