// Authentication + tenant-resolution middleware.
//
// Every API request must carry a tenant API key (Authorization: Bearer ...
// or X-API-Key). The key is hashed and looked up; on success the request
// gets a tenant-scoped repository at req.repo so handlers can NEVER touch
// another tenant's data. There is no global db handle in the route layer.
import { global, forTenant } from '../db/index.js';
import { hashApiKey } from '../utils/crypto.js';

// Extract the presented key from the standard places.
function extractKey(req) {
  const auth = req.get('authorization');
  if (auth && /^bearer\s+/i.test(auth)) return auth.replace(/^bearer\s+/i, '').trim();
  const x = req.get('x-api-key');
  if (x) return x.trim();
  return null;
}

export function requireApiKey(req, res, next) {
  const key = extractKey(req);
  if (!key) {
    // Generic message — no hint about whether the header or the key is the
    // problem (avoids aiding credential probing).
    return res.status(401).json({ error: 'Authentication required.' });
  }
  const tenant = global.findTenantByKeyHash(hashApiKey(key));
  if (!tenant) {
    return res.status(401).json({ error: 'Invalid credentials.' });
  }
  req.tenant = { id: tenant.id, name: tenant.name, plan: tenant.plan };
  // Scoped repository — carries the webhook secret for outbound signing.
  req.repo = forTenant(tenant.id, tenant.webhook_secret);
  next();
}

// Async handler wrapper so thrown errors reach the error middleware
// instead of crashing the process or hanging the request.
export function asyncHandler(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}
