# ── Stage 1: Build the Vite app ──────────────────────────────────────────────
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY index.html vite.config.js ./
COPY src ./src
RUN npm run build

# ── Stage 2: nginx serving the built app ─────────────────────────────────────
FROM nginx:1.29-alpine

# Upgrade all OS packages to pick up Alpine security patches
RUN apk upgrade --no-cache

# Remove default config
RUN rm /etc/nginx/conf.d/default.conf

# Copy our config
COPY nginx/nginx.conf      /etc/nginx/conf.d/app.conf
COPY nginx/rate-limit.conf /etc/nginx/conf.d/rate-limit.conf

# Copy the built app and login page
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx/login.html         /usr/share/nginx/html/login.html

# Entrypoint script generates /config.js from environment variables at startup
COPY nginx/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80

ENTRYPOINT ["/entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]
