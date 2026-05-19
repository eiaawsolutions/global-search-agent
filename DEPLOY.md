# Deploying the Global Search Agent

The app is a self-contained Node.js service. It runs **permanently and
independently** once deployed — no dependency on Claude, Anthropic, or any AI
service. The same Docker image runs on **Railway** and **GCP Cloud Run**.

> **Cost note.** The agent itself has **no per-request or AI cost**. Linking it
> to another app's API costs nothing on the agent's side — it makes plain HTTP
> calls. Your only costs are the host (Railway / GCP) and, if applicable, the
> connected app's own API pricing.

---

## Generate your secrets first (both platforms)

You need three values. Generate them once and keep them safe:

```bash
# ENCRYPTION_KEY — 64 hex chars (encrypts connector credentials at rest)
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

# SESSION_SECRET — 64 hex chars
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

# BOOTSTRAP_API_KEY — the tenant API key you'll use to log into the console
node -e "console.log('gsa_'+require('crypto').randomBytes(24).toString('hex'))"
```

Pinning `BOOTSTRAP_API_KEY` means the login key is known up front and never
lost in container logs.

---

## Option A — Railway (recommended for SQLite)

Railway gives a real persistent block volume, which is the natural fit for
SQLite. This is the simplest permanent host.

### Via the Railway CLI

```bash
# 1. Log in (opens a browser)
railway login

# 2. From the project directory, create a new project
cd "global-search-agent"
railway init --name "Global search agent"

# 3. Add a persistent volume mounted at /data (where the SQLite file lives)
#    — do this in the Railway dashboard: Service → Settings → Volumes →
#      New Volume → mount path: /data
#    (CLI volume support varies by version; the dashboard is reliable.)

# 4. Set environment variables
railway variables --set "NODE_ENV=production" \
  --set "DB_PATH=/data/search-agent.db" \
  --set "ENCRYPTION_KEY=<your 64-hex key>" \
  --set "SESSION_SECRET=<your 64-hex secret>" \
  --set "BOOTSTRAP_API_KEY=<your gsa_ key>" \
  --set "BOOTSTRAP_TENANT_NAME=Global Search Agent"

# 5. Deploy (builds the Dockerfile, pushes, releases)
railway up

# 6. Generate a public URL
railway domain
```

Railway auto-injects `PORT`; the app reads it. The health check at `/health`
is already configured in `railway.json`.

### Via the Railway dashboard

1. **New Project** → name it **Global search agent**.
2. **Deploy from GitHub repo** (push this code to GitHub first) or
   **Empty Service** + `railway up` from the CLI.
3. **Service → Settings → Volumes** → add a volume, mount path **`/data`**.
4. **Service → Variables** → add the env vars from step 4 above.
5. Railway builds from the `Dockerfile` automatically and deploys.
6. **Settings → Networking → Generate Domain** for a public URL.

---

## Option B — GCP Cloud Run

Cloud Run's local filesystem is ephemeral. The deploy script mounts a **GCS
bucket** as a volume for the SQLite file and pins the service to **one
instance** (SQLite is single-writer).

> If you expect heavier concurrent load, migrate to **Cloud SQL (Postgres)**
> instead — the data layer in `src/db/index.js` is abstracted for that. For
> this app's scale, single-instance + GCS volume is fine.

### Prerequisites

- Install the gcloud CLI: <https://cloud.google.com/sdk/docs/install>
- `gcloud auth login` and `gcloud config set project <PROJECT_ID>`

### Deploy

```bash
cd "global-search-agent"

export PROJECT_ID="your-gcp-project"
export REGION="asia-southeast1"          # or your preferred region
export ENCRYPTION_KEY="<your 64-hex key>"
export SESSION_SECRET="<your 64-hex secret>"
export BOOTSTRAP_API_KEY="<your gsa_ key>"

bash deploy/deploy-gcp.sh
```

The script enables APIs, creates the Artifact Registry repo + GCS bucket,
builds & pushes the image, and deploys. It prints the public URL at the end.

For production, move the three secrets into **Secret Manager** and change the
script's `--update-env-vars` lines to `--set-secrets`.

---

## Verify the deployment (both platforms)

```bash
curl https://<your-deployed-url>/health
# → {"status":"ok","service":"global-search-agent",...}
```

Then open `https://<your-deployed-url>/` in a browser, paste your
`BOOTSTRAP_API_KEY` into the **Tenant API key** field, and click **Connect**.

---

## Run the container locally (optional sanity check)

```bash
docker build -t global-search-agent .

docker run --rm -p 8080:8080 \
  -e ENCRYPTION_KEY=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))") \
  -e SESSION_SECRET=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))") \
  -v gsa-data:/data \
  global-search-agent
# → open http://localhost:8080
```

The named volume `gsa-data` persists the SQLite file across container restarts.

---

## Updating a deployed instance

- **Railway**: `railway up` again (or push to the connected GitHub branch).
- **GCP**: re-run `bash deploy/deploy-gcp.sh`.

The schema migration is idempotent and runs automatically on every boot;
existing data on the volume is preserved. The bootstrap tenant is created only
once — subsequent boots skip it.

---

## Environment variables reference

| Variable | Required | Purpose |
|---|---|---|
| `ENCRYPTION_KEY` | **yes** (prod) | 64 hex chars — AES-256-GCM for connector credentials |
| `SESSION_SECRET` | **yes** (prod) | 64 hex chars — cookie/session signing |
| `DB_PATH` | yes (hosted) | Point at the mounted volume, e.g. `/data/search-agent.db` |
| `BOOTSTRAP_API_KEY` | recommended | Pins the tenant login key (≥24 chars); else generated |
| `BOOTSTRAP_WEBHOOK_SECRET` | optional | Pins the webhook signing secret; else generated |
| `BOOTSTRAP_TENANT_NAME` | optional | Display name for the first tenant |
| `PORT` | auto | Injected by Railway / Cloud Run; do not set manually |
| `RATE_LIMIT_PER_MIN` | optional | Per-tenant API rate limit (default 120) |
| `MAX_CSV_BYTES` / `MAX_CSV_ROWS` | optional | CSV upload caps |
| `ALLOW_PRIVATE_CONNECTORS` | **never in prod** | Dev/CI only; force-disabled when `NODE_ENV=production` |
