# Global Search Agent

A multi-tenant service that connects to **any application** via API or webhook,
sweeps that application's database, and tells you which of your input records
are **duplicates** (with the exact data point that made them a duplicate),
which need **review**, and which are **new** — surfacing the new ones as leads
with a one-click "add to lead listing" action.

- **Deterministic + explainable matching** — normalization + fuzzy similarity
  (Jaro-Winkler, Levenshtein, token-set). No LLM in the hot path: fast, cheap,
  reproducible, and every verdict carries its evidence.
- **Per-app API contract** — the agent never touches a connected app's
  database directly. Each app exposes two small HTTP endpoints; the agent
  speaks a fixed contract to them. Works against any schema via a field map.
- **Multi-tenant** — every row is tenant-scoped; isolation is enforced in the
  data layer and proven by an automated cross-tenant leakage test.
- **Secure by default** — API-key auth, HMAC-signed webhooks, SSRF guard on
  connector URLs, encrypted connector credentials, rate limiting, security
  headers, no information disclosure.

---

## Quick start

```bash
npm install
cp .env.example .env          # then set ENCRYPTION_KEY + SESSION_SECRET
npm start
```

On first boot the agent applies the schema and prints a **bootstrap tenant
API key** and **webhook secret** to the console — store them; the key is not
recoverable. Then open <http://localhost:4100>.

```bash
npm test          # unit + integration suite (28 tests)
npm run test:smoke   # full end-to-end smoke test against a mock connected app
```

---

## How it works

```
Input records ─▶ Normalize ─▶ Ask the connected app for candidates
                                        │
                                        ▼
                          Match engine (per the chosen criteria)
                                        │
                       ┌────────────────┼────────────────┐
                       ▼                ▼                ▼
                  DUPLICATE          REVIEW             NEW
              (≥ 0.85, with      (0.60–0.85, a      (< 0.60 — surfaced
               a strong ID or     human decides)     as a lead with the
               ≥2 fields)                            "add lead" CTA)
```

**Match criteria** are chosen per job — any combination of `name`, `email`,
`phone`, `company`, `location`. Only the selected fields contribute to a verdict.

**Confidence guard.** A high score driven by a *single fuzzy attribute* (a
similar name and nothing else) is capped at `review` — a name is not a unique
identifier. A `duplicate` verdict requires either an exact strong-identifier
match (email/phone) or corroboration across ≥2 fields. Records are never merged
on a hunch.

---

## Connecting an application

Connectors have a **kind** that selects the transport adapter:

- **`generic`** (default) — the application implements the agent's fixed
  two-endpoint contract (below). Use this for apps you control.
- **`vistage`** — a built-in adapter for the **Vistage / Claritas CRM** `.svc`
  API. The CRM keeps its own auth and JSON shape; the adapter handles HMAC
  signing, token caching, and `GetList` paging. **Read-only** — Vistage has no
  contact-create endpoint, so the add-lead CTA is disabled for these
  connectors. See [Vistage connector](#vistage-connector) below.

New CRMs are added by dropping one adapter module in `src/connectors/` and
registering it in the `ADAPTERS` map in `src/connectors/client.js`.

## The per-app API contract (generic kind)

To connect an application you control, that application exposes **two
endpoints**. Register them as a *connector* (via the UI or
`POST /api/connectors`).

### 1. Search endpoint — read candidates

```
POST {base_url}{search_path}        default search_path: /records/search
Authorization: <connector credential>     (as configured)
Content-Type: application/json

{
  "criteria": ["email", "name"],
  "query":    { "email": "jane@acme.com", "name": "Jane Doe" },
  "limit":    200
}
```

Respond with candidate records — your app decides how to search them:

```json
{ "records": [ { "id": "c1", "full_name": "Jane Doe", "email_address": "jane@acme.com" } ] }
```

Your field names don't have to match ours. Supply a **field map** on the
connector and the agent translates them:

```json
{ "field_map": { "name": "full_name", "email": "email_address", "company": "org" } }
```

### 2. Create-lead endpoint — receive a new lead

Called **only** when a user clicks "Add to lead listing" on a `new` result —
never automatically.

```
POST {base_url}{create_path}        default create_path: /leads

{ "lead": { "name": "...", "email": "...", "phone": "...",
            "company": "...", "location": "...", "source": "global-search-agent" } }
```

Respond with the created id (optional):

```json
{ "id": "lead-123" }
```

---

## Vistage connector

The **Vistage / Claritas CRM** uses its own HMAC-signed `.svc` API, so it
cannot adopt the generic contract above. Register it with `kind: "vistage"`:

```bash
curl -X POST http://localhost:4100/api/connectors \
  -H "Authorization: Bearer gsa_..." \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Vistage Staging",
    "kind": "vistage",
    "base_url": "https://teststudio.claritascrm.com/api/VistageService.svc",
    "vistage": {
      "client_id": "<Client ID>",
      "secret_key": "<Secret Key>",
      "username":   "<API user>",
      "password":   "<API password>"
    },
    "modules": ["ActiveMember", "InWaitingMember", "Prospect"],
    "field_map": { "name": "name2", "phone": "Mobile" }
  }'
```

- **Auth** — the adapter signs every request with HMAC-SHA256 (`Signature 1`
  for `/token`, `Signature 2` for function calls) and caches the access token.
- **UserToken** — `GetList` needs a `UserToken`. The adapter obtains it via
  `UserLogin` using `username`/`password`. If your Vistage instance does not
  provision a login for API use, supply a pre-known token at registration with
  a `user_token` object (`{ UserId, UserName, Role }`) instead.
- **`modules`** — which member lists to sweep. Valid: `ActiveMember`,
  `InWaitingMember`, `LOAMember`, `TerminatedMember`, `Prospect`. Defaults to
  `ActiveMember` + `Prospect`.
- **`field_map`** — Vistage member rows put the name in `name2` and the phone
  in `Mobile`; rows carry no email or company. Map fields to taste.
- **Read-only** — Vistage has no contact-create endpoint, so the add-lead CTA
  returns `409` for these connectors.

Verify connectivity against staging without touching the agent:

```bash
npm run test:vistage          # token + UserLogin + GetList probe
npm run test:vistage:sweep    # full end-to-end sweep through the agent
```

---

## REST API

All `/api` routes require the tenant API key as `Authorization: Bearer <key>`
or `X-API-Key: <key>`.

| Method & path | Purpose |
|---|---|
| `POST /api/connectors` | Register a connected application |
| `GET  /api/connectors` | List connectors |
| `POST /api/search` | Run a sweep from a JSON list of records |
| `POST /api/search/csv` | Run a sweep from a CSV upload or a pasted name list |
| `GET  /api/search/:id` | Job status + rollup counts |
| `GET  /api/search/:id/results?classification=duplicate\|review\|new` | Classified results with evidence |
| `POST /api/results/:id/add-lead` | The CTA — push a `new` record to the connected app |
| `GET  /api/jobs` | Recent jobs |
| `POST /api/webhook/search` | HMAC-signed sweep trigger (for app-to-agent integration) |

### Create a sweep

```bash
curl -X POST http://localhost:4100/api/search \
  -H "Authorization: Bearer gsa_..." \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: import-2026-05-19" \
  -d '{
    "connector_id": "<id>",
    "criteria": ["email", "phone", "name"],
    "records": [
      { "name": "Jane Doe", "email": "jane@acme.com" },
      { "name": "Ahmad Ismail", "phone": "+60123456789" }
    ]
  }'
```

A result's `matched_on` array names exactly which data points triggered a
duplicate, each with its own similarity score:

```json
{
  "classification": "duplicate",
  "score": 0.92,
  "explanation": "Duplicate — matched on email (100%), name (80%).",
  "matched_on": [
    { "field": "email", "score": 1.0,  "inputValue": "jane@acme.com", "matchValue": "jane@acme.com" },
    { "field": "name",  "score": 0.80, "inputValue": "Jane D.",       "matchValue": "Jane Doe" }
  ],
  "matched_record": { "...": "the connected-app record" }
}
```

### Inbound webhook (app triggers a sweep)

Sign the **raw body** with the tenant webhook secret:

```
signature = HMAC_SHA256(webhook_secret, `${timestamp}.${rawBody}`)
```

```
POST /api/webhook/search
X-API-Key:       gsa_...
X-GSA-Timestamp: 1716100000
X-GSA-Signature: <hex>
```

When a job completes, the agent POSTs a signed callback to
`{base_url}/gsa-callback` (verify it with the same secret).

---

## Security

| Threat | Mitigation |
|---|---|
| Spoofing | API keys hashed (SHA-256) at rest; HMAC-SHA256 signed webhooks with a replay window |
| Tampering | Idempotency keys on ingest; raw-body signature verification on inbound webhooks |
| Cross-tenant access | Every query tenant-scoped in the data layer; automated leakage test |
| SSRF via connector URLs | Connector hosts resolving to private/loopback/link-local ranges are refused |
| Credential exposure | Connected-app credentials encrypted with AES-256-GCM; never returned by the API |
| Abuse / DoS | Per-tenant rate limiting; CSV byte + row caps; outbound request timeouts |
| Information disclosure | No stack traces, no version headers, generic auth errors |

> `ALLOW_PRIVATE_CONNECTORS=true` permits private/loopback connector hosts for
> local development and CI only. It is **force-disabled** when
> `NODE_ENV=production`.

---

## Project layout

```
src/
  config.js              env loading + validation
  server.js              Express app, middleware, route wiring
  db/
    schema.sql           multi-tenant schema
    index.js             connection + tenant-scoped repository
    migrate.js           schema apply + bootstrap tenant
  matching/
    normalize.js         field normalization (email/phone/name/company/location)
    similarity.js        Levenshtein, Jaro-Winkler, token-set primitives
    engine.js            per-field matchers, scoring, classification, evidence
  connectors/
    client.js            the per-app API contract (fetch candidates / push lead)
    ssrf-guard.js         private-address rejection for connector URLs
  ingest/csv.js          dependency-free RFC-4180 CSV + name-list parsing
  sweep/orchestrator.js  runs a job end-to-end (bounded concurrency)
  webhooks/dispatcher.js HMAC-signed outbound callbacks
  routes/                connectors, search, webhook
  middleware/            auth + tenant scoping, error handling
public/                  self-contained web console (HTML + CSS + vanilla JS)
test/                    unit + integration suite, plus the e2e smoke test
```

---

## Limitations & follow-ups

- **Sweeps run synchronously** within the request (sized for ≤ 10k records).
  For larger jobs, move `runSweep` onto a job queue — the orchestrator is
  already structured as the seam for that.
- **Storage is SQLite.** The data layer is abstracted behind the tenant-scoped
  repository; swapping to Postgres (with native row-level security) is a
  contained change if a tenant needs DB-level isolation or higher concurrency.
- **Bootstrap tenant only.** Tenant self-service signup, plan tiers, and
  usage-based billing are not built — add when productizing.
- The matching weights and thresholds in `src/matching/engine.js` are tuned
  for general contact data; adjust per dataset if needed.
