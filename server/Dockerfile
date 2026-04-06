FROM node:20-alpine

WORKDIR /app

# Install native build tools needed by better-sqlite3
RUN apk add --no-cache python3 make g++

COPY package.json ./
RUN npm install --omit=dev

COPY server.js ./

# Data volume — SQLite database lives here
VOLUME ["/data"]

EXPOSE 3000

CMD ["node", "server.js"]
