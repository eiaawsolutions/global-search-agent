// Outbound webhook dispatcher.
//
// When a search job completes, the agent can notify the connected app. The
// payload is HMAC-SHA256 signed with the tenant's webhook secret and carries
// a timestamp so the receiver can verify authenticity and bound replay.
//
// Headers the receiver checks:
//   X-GSA-Signature : hex HMAC-SHA256 of `${timestamp}.${rawBody}`
//   X-GSA-Timestamp : unix seconds
//   X-GSA-Event     : event name
import { signWebhook } from '../utils/crypto.js';
import { assertSafeUrl } from '../connectors/ssrf-guard.js';
import { config } from '../config.js';

const TIMEOUT_MS = 8_000;
const MAX_ATTEMPTS = 3;

// Send one signed webhook with bounded retries (exponential backoff).
// `targetUrl` is resolved from the connector's base_url + a fixed callback
// path so the operator does not configure a separate URL.
export async function dispatchWebhook({ repo, job, event, payload }) {
  // The completion callback goes to the connector's base host. If no
  // connector context is available, there is nowhere to deliver — skip.
  const connector = job?.connector_id
    ? repo.getConnector(job.connector_id)
    : null;
  if (!connector) return { skipped: true };

  const targetUrl =
    connector.base_url.replace(/\/+$/, '') + '/gsa-callback';

  // The tenant's webhook secret is carried on the scoped repository.
  const secret = repo.webhookSecret;
  const body = JSON.stringify({ event, data: payload });
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const signature = secret ? signWebhook(secret, timestamp, body) : '';

  let lastError = null;
  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    try {
      await assertSafeUrl(targetUrl, {
        requireHttps: config.isProd,
        allowPrivate: config.allowPrivateConnectors,
      });
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
      try {
        const res = await fetch(targetUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-GSA-Signature': signature,
            'X-GSA-Timestamp': timestamp,
            'X-GSA-Event': event,
            'User-Agent': 'GlobalSearchAgent/1.0',
          },
          body,
          signal: controller.signal,
          redirect: 'error',
        });
        if (res.ok) {
          repo.recordWebhook({
            jobId: job.id,
            targetUrl,
            event,
            status: 'delivered',
            attempts: attempt,
            deliveredAt: new Date().toISOString(),
          });
          return { delivered: true, attempts: attempt };
        }
        lastError = `HTTP ${res.status}`;
      } finally {
        clearTimeout(timer);
      }
    } catch (err) {
      lastError = err.message;
    }
    // Backoff before the next attempt: 0.5s, 1s.
    if (attempt < MAX_ATTEMPTS) {
      await new Promise((r) => setTimeout(r, 500 * attempt));
    }
  }

  repo.recordWebhook({
    jobId: job.id,
    targetUrl,
    event,
    status: 'failed',
    attempts: MAX_ATTEMPTS,
    lastError,
  });
  return { delivered: false, error: lastError };
}
