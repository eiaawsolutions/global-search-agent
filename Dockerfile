# Global Search Agent — production image.
# Multi-stage: the builder compiles better-sqlite3's native addon (needs
# python3 + a C++ toolchain); the runtime stage is slim and carries only the
# compiled node_modules + app source. The same image runs on Railway and on
# GCP Cloud Run — both just need the container to listen on $PORT.

# ── Stage 1: build native deps ───────────────────────────────────────
FROM node:20-bookworm-slim AS builder
WORKDIR /app

# Toolchain for node-gyp / better-sqlite3. Confined to the builder stage so
# none of it ships in the final image.
RUN apt-get update \
  && apt-get install -y --no-install-recommends python3 make g++ \
  && rm -rf /var/lib/apt/lists/*

# Install production dependencies only. Copying package files first keeps
# this layer cached when only application source changes.
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev

# ── Stage 2: runtime ─────────────────────────────────────────────────
FROM node:20-bookworm-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production

# tini  = a proper PID 1 so SIGTERM reaches Node for graceful shutdown.
# gosu  = drop privileges from root → node inside the entrypoint AFTER the
#         persistent volume has been chowned (the volume mounts over /data
#         owned by root, masking any build-time chown — see entrypoint).
RUN apt-get update \
  && apt-get install -y --no-install-recommends tini gosu \
  && rm -rf /var/lib/apt/lists/*

# Compiled dependencies from the builder, then application source.
COPY --from=builder /app/node_modules ./node_modules
COPY package.json ./
COPY src ./src
COPY public ./public
COPY scripts ./scripts
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# The SQLite volume mounts here (see railway.json / Cloud Run volume).
# DB_PATH defaults to this location; create it so the dir exists even before
# a volume is attached (local `docker run` without -v still works).
RUN mkdir -p /data
ENV DB_PATH=/data/search-agent.db

# /app is owned by node at build time. /data is fixed up at RUNTIME by the
# entrypoint, because the volume mount replaces it. The container therefore
# starts as ROOT (no `USER node` here) so the entrypoint can chown the mount;
# it then drops to `node` via gosu before exec-ing the app.
RUN chown -R node:node /app

# Cloud Run injects PORT (default 8080); Railway injects its own. The app
# reads process.env.PORT — default here is 8080 so a bare `docker run` works.
ENV PORT=8080
EXPOSE 8080

# Container-level health probe. Railway/Cloud Run also probe over HTTP; this
# gives `docker ps` a status too. Uses Node (no curl in the slim image).
HEALTHCHECK --interval=30s --timeout=4s --start-period=8s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8080)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

# tini as PID 1 → entrypoint (chowns the volume, drops to `node`) → the app.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/docker-entrypoint.sh"]
CMD ["node", "src/server.js"]
