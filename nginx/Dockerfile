FROM nginx:1.27-alpine

# Remove default config
RUN rm /etc/nginx/conf.d/default.conf

# Copy our config (build context is the repo root)
COPY nginx/nginx.conf      /etc/nginx/conf.d/app.conf
# Rate-limit zones must be at the http context level; conf.d/ files are
# auto-included inside nginx's http block by the default nginx.conf.
COPY nginx/rate-limit.conf /etc/nginx/conf.d/rate-limit.conf

# Copy the static app and login page
COPY index.html               /usr/share/nginx/html/index.html
COPY nginx/login.html         /usr/share/nginx/html/login.html

# Entrypoint script generates /config.js from environment variables at startup,
# then starts Nginx normally.
COPY nginx/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80

ENTRYPOINT ["/entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]
