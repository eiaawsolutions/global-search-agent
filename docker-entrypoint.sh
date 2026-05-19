#!/bin/sh
# Container entrypoint.
#
# A persistent volume (Railway / Cloud Run) mounts OVER /data at runtime and
# arrives owned by root — that masks the build-time `chown` in the Dockerfile,
# so the unprivileged `node` user cannot create the SQLite file and the app
# crashes with SQLITE_CANTOPEN. We fix ownership here, at start, when the
# mount is actually present, then drop privileges to `node` to run the app.
set -e

DATA_DIR="$(dirname "${DB_PATH:-/data/search-agent.db}")"
mkdir -p "$DATA_DIR"

# Only root can chown; if we're already `node` (e.g. local `docker run`
# without a root-owned mount) just continue.
if [ "$(id -u)" = "0" ]; then
  chown -R node:node "$DATA_DIR" || true
  # Re-exec the app as `node` via gosu/su-exec if available, else su.
  if command -v gosu >/dev/null 2>&1; then
    exec gosu node "$@"
  else
    exec su -s /bin/sh node -c '"$0" "$@"' -- "$@"
  fi
fi

exec "$@"
