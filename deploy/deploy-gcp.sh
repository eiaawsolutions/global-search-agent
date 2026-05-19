#!/usr/bin/env bash
# Deploy the Global Search Agent to GCP Cloud Run.
#
# This script: enables APIs, creates an Artifact Registry repo + a GCS bucket
# for the SQLite volume, builds & pushes the image, and deploys the service.
#
# IMPORTANT — SQLite on Cloud Run:
#   Cloud Run's local filesystem is ephemeral. To persist the SQLite file we
#   mount a GCS bucket as a volume. SQLite is a SINGLE-WRITER database, so the
#   service is pinned to exactly one instance (min=max=1). This is correct for
#   this workload's scale. If you outgrow it, migrate to Cloud SQL (Postgres)
#   — see DEPLOY.md. Railway, with a real block-volume, is the simpler host
#   for SQLite; GCP here is the portable alternative you asked for.
#
# Prereqs: gcloud CLI installed and authenticated (`gcloud auth login`).
# Usage:   PROJECT_ID=my-proj ./deploy/deploy-gcp.sh
set -euo pipefail

# ── Config (override via env) ────────────────────────────────────────
PROJECT_ID="${PROJECT_ID:?set PROJECT_ID=your-gcp-project}"
REGION="${REGION:-asia-southeast1}"
SERVICE="${SERVICE:-global-search-agent}"
REPO="${REPO:-global-search-agent}"
BUCKET="${BUCKET:-${PROJECT_ID}-gsa-data}"
IMAGE="${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO}/${SERVICE}:latest"

echo "▶ Project ${PROJECT_ID} | Region ${REGION} | Service ${SERVICE}"

# ── 1. Enable required APIs (idempotent) ─────────────────────────────
echo "▶ Enabling APIs…"
gcloud services enable \
  run.googleapis.com \
  cloudbuild.googleapis.com \
  artifactregistry.googleapis.com \
  storage.googleapis.com \
  --project "${PROJECT_ID}"

# ── 2. Artifact Registry repo for the image ──────────────────────────
if ! gcloud artifacts repositories describe "${REPO}" \
      --location "${REGION}" --project "${PROJECT_ID}" >/dev/null 2>&1; then
  echo "▶ Creating Artifact Registry repo ${REPO}…"
  gcloud artifacts repositories create "${REPO}" \
    --repository-format=docker --location "${REGION}" \
    --description "Global Search Agent images" --project "${PROJECT_ID}"
fi

# ── 3. GCS bucket for the SQLite volume ──────────────────────────────
if ! gcloud storage buckets describe "gs://${BUCKET}" --project "${PROJECT_ID}" >/dev/null 2>&1; then
  echo "▶ Creating GCS bucket gs://${BUCKET} for the SQLite volume…"
  gcloud storage buckets create "gs://${BUCKET}" \
    --location "${REGION}" --uniform-bucket-level-access --project "${PROJECT_ID}"
fi

# ── 4. Build & push the image ────────────────────────────────────────
echo "▶ Building & pushing image via Cloud Build…"
gcloud builds submit --tag "${IMAGE}" --project "${PROJECT_ID}" .

# ── 5. Deploy to Cloud Run ───────────────────────────────────────────
# - SQLite is single-writer → exactly one instance.
# - The GCS bucket is mounted at /data; DB_PATH points the app there.
# - Secrets are passed as env vars (standalone project, per your decision).
#   For production, prefer --set-secrets with Secret Manager.
echo "▶ Deploying to Cloud Run…"
gcloud run deploy "${SERVICE}" \
  --image "${IMAGE}" \
  --region "${REGION}" \
  --project "${PROJECT_ID}" \
  --platform managed \
  --allow-unauthenticated \
  --port 8080 \
  --min-instances 1 \
  --max-instances 1 \
  --cpu 1 --memory 512Mi \
  --add-volume "name=gsa-data,type=cloud-storage,bucket=${BUCKET}" \
  --add-volume-mount "volume=gsa-data,mount-path=/data" \
  --set-env-vars "NODE_ENV=production,DB_PATH=/data/search-agent.db,BOOTSTRAP_TENANT_NAME=Global Search Agent" \
  --update-env-vars "ENCRYPTION_KEY=${ENCRYPTION_KEY:?set ENCRYPTION_KEY (64 hex chars)}" \
  --update-env-vars "SESSION_SECRET=${SESSION_SECRET:?set SESSION_SECRET (64 hex chars)}" \
  --update-env-vars "BOOTSTRAP_API_KEY=${BOOTSTRAP_API_KEY:?set BOOTSTRAP_API_KEY (>=24 chars)}"

URL="$(gcloud run services describe "${SERVICE}" --region "${REGION}" \
       --project "${PROJECT_ID}" --format 'value(status.url)')"
echo ""
echo "✅ Deployed: ${URL}"
echo "   Health  : ${URL}/health"
echo "   Console : ${URL}/"
