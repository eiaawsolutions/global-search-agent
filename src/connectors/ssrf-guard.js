// SSRF guard for connector URLs.
//
// A connector base_url is operator-supplied and the agent makes outbound
// HTTP requests to it. Without a guard, a tenant could point a connector at
// http://169.254.169.254/ (cloud metadata) or an internal service and use
// the agent as a confused-deputy proxy. This module rejects any URL that
// resolves into a private / link-local / loopback range before a request
// is made.
import dns from 'node:dns/promises';
import net from 'node:net';

// IPv4 ranges that must never be reachable via a connector.
function isPrivateV4(ip) {
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some((n) => Number.isNaN(n))) return true; // fail closed
  const [a, b] = p;
  if (a === 10) return true; // 10.0.0.0/8
  if (a === 127) return true; // loopback
  if (a === 0) return true; // 0.0.0.0/8
  if (a === 169 && b === 254) return true; // link-local incl. cloud metadata
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 192 && b === 168) return true; // 192.168.0.0/16
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64.0.0/10
  if (a >= 224) return true; // multicast / reserved
  return false;
}

function isPrivateV6(ip) {
  const v = ip.toLowerCase();
  if (v === '::1' || v === '::') return true; // loopback / unspecified
  if (v.startsWith('fe80')) return true; // link-local
  if (v.startsWith('fc') || v.startsWith('fd')) return true; // unique-local
  if (v.startsWith('::ffff:')) return isPrivateV4(v.split(':').pop()); // mapped v4
  return false;
}

function isPrivate(ip) {
  return net.isIPv6(ip) ? isPrivateV6(ip) : isPrivateV4(ip);
}

// Validate a URL's *shape* (sync) — scheme and an explicit non-private
// literal host. In production a host must be HTTPS. `allowPrivate` (dev/CI
// only) skips the private-address rejection so a mock app on 127.0.0.1 can
// be swept; it is never true in production (enforced in config.js).
export function assertSafeUrlShape(rawUrl, { requireHttps, allowPrivate } = {}) {
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new Error('Connector URL is not a valid URL.');
  }
  if (!['http:', 'https:'].includes(url.protocol)) {
    throw new Error('Connector URL must use http or https.');
  }
  if (requireHttps && url.protocol !== 'https:') {
    throw new Error('Connector URL must use https in production.');
  }
  const host = url.hostname;
  if (allowPrivate) return url; // dev/CI escape hatch
  // Literal IP host → check immediately.
  if (net.isIP(host) && isPrivate(host)) {
    throw new Error('Connector URL resolves to a private/internal address.');
  }
  if (host === 'localhost' || host.endsWith('.localhost')) {
    throw new Error('Connector URL must not target localhost.');
  }
  return url;
}

// Full check (async) — also resolves DNS and rejects if ANY resolved
// address is private. Call this right before making the request.
export async function assertSafeUrl(rawUrl, opts = {}) {
  const url = assertSafeUrlShape(rawUrl, opts);
  if (opts.allowPrivate) return url; // dev/CI escape hatch
  const host = url.hostname;
  if (net.isIP(host)) return url; // already checked in shape pass

  let addrs = [];
  try {
    addrs = await dns.lookup(host, { all: true });
  } catch {
    throw new Error(`Connector host could not be resolved: ${host}`);
  }
  for (const { address } of addrs) {
    if (isPrivate(address)) {
      throw new Error(
        `Connector host ${host} resolves to a private address — refused.`
      );
    }
  }
  return url;
}

export { isPrivate };
