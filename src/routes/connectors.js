// Connector routes — register and list the connected applications a tenant
// can sweep. Credentials are encrypted before storage; they are never
// returned in any response.
import { Router } from 'express';
import { asyncHandler } from '../middleware/auth.js';
import { encrypt } from '../utils/crypto.js';
import { assertSafeUrlShape } from '../connectors/ssrf-guard.js';
import { probe } from '../connectors/client.js';
import { VISTAGE_MODULES } from '../connectors/vistage.js';
import { config } from '../config.js';

const router = Router();

const CONNECTOR_KINDS = ['generic', 'vistage'];

// Strip secret-bearing fields from a connector row before returning it.
function publicConnector(c) {
  const meta = safeParse(c.meta_json);
  return {
    id: c.id,
    name: c.name,
    kind: c.kind || 'generic',
    base_url: c.base_url,
    search_path: c.search_path,
    create_path: c.create_path,
    auth_type: c.auth_type,
    status: c.status,
    created_at: c.created_at,
    has_credential: !!c.credential_enc,
    // Non-secret kind settings only (e.g. vistage modules). UserToken is
    // operational state — surface just whether it's resolved.
    modules: meta.modules || undefined,
    // Vistage gained write-back in Common API V1 (Save - Lead); previously
    // read-only.
    supports_lead_push:
      (c.kind || 'generic') === 'generic' || c.kind === 'vistage',
  };
}

function safeParse(json) {
  try {
    return JSON.parse(json || '{}');
  } catch {
    return {};
  }
}

// GET /api/connectors — list this tenant's connectors.
router.get(
  '/',
  asyncHandler(async (req, res) => {
    res.json({ connectors: req.repo.listConnectors().map(publicConnector) });
  })
);

// POST /api/connectors — register a connected application.
//
// Two shapes, selected by `kind`:
//   kind=generic (default) — { name, base_url, search_path, create_path,
//     auth_type, auth_header, credential, field_map }
//   kind=vistage           — { name, base_url, vistage:{ client_id,
//     secret_key, username, password }, user_token?:{ CompanyId,
//     CompanyPrefix, UserId, UserModuleId, UserName }, modules?,
//     default_branch?, field_map? }
router.post(
  '/',
  asyncHandler(async (req, res) => {
    const b = req.body || {};
    if (!b.name || !b.base_url) {
      return res.status(400).json({ error: 'name and base_url are required.' });
    }
    const kind = CONNECTOR_KINDS.includes(b.kind) ? b.kind : 'generic';

    // SSRF shape check up front — reject private/loopback hosts immediately.
    try {
      assertSafeUrlShape(b.base_url, {
        requireHttps: config.isProd,
        allowPrivate: config.allowPrivateConnectors,
      });
    } catch (err) {
      return res.status(400).json({ error: err.message });
    }

    const fieldMap =
      b.field_map && typeof b.field_map === 'object' ? b.field_map : {};

    let connectorInput;
    if (kind === 'vistage') {
      // Vistage stores its 4 secrets as one encrypted JSON bundle.
      const v = b.vistage || {};
      if (!v.client_id || !v.secret_key) {
        return res.status(400).json({
          error: 'vistage.client_id and vistage.secret_key are required.',
        });
      }
      const bundle = {
        clientId: String(v.client_id),
        secretKey: String(v.secret_key),
        userName: v.username ? String(v.username) : '',
        password: v.password ? String(v.password) : '',
      };
      // `modules` narrows which lists are swept; default in adapter
      // (V1 canonical modules: Lead, Member, Contact, Account).
      const modules = Array.isArray(b.modules)
        ? b.modules.filter((m) => VISTAGE_MODULES.includes(m))
        : [];
      const meta = {};
      if (modules.length) meta.modules = modules;
      // Optional default Branch for Save - Lead. Stored alongside modules so
      // the createLead path picks it up without re-asking the operator.
      if (b.default_branch) {
        meta.defaultBranch = String(b.default_branch).slice(0, 200);
      }
      // Optional pre-known UserToken — for Vistage instances where UserLogin
      // is not provisioned for API use and the integrator supplies the token
      // out of band. When omitted, the adapter resolves it via UserLogin.
      // V1 shape: { CompanyId, CompanyPrefix, UserId, UserModuleId, UserName }.
      const ut = b.user_token;
      if (ut && ut.UserId && ut.UserName) {
        const companyId = parseInt(ut.CompanyId, 10);
        if (!Number.isFinite(companyId) || companyId <= 0) {
          return res.status(400).json({
            error:
              'vistage.user_token.CompanyId is required (Common API V1 path segment).',
          });
        }
        meta.userToken = {
          CompanyId: companyId,
          CompanyPrefix: ut.CompanyPrefix ? String(ut.CompanyPrefix) : null,
          UserId: String(ut.UserId),
          UserModuleId: parseInt(ut.UserModuleId, 10) || 0,
          UserName: String(ut.UserName),
        };
      }
      connectorInput = {
        name: String(b.name).slice(0, 120),
        kind: 'vistage',
        base_url: String(b.base_url).slice(0, 500),
        credential_enc: encrypt(JSON.stringify(bundle)),
        field_map_json: JSON.stringify(fieldMap),
        meta_json: JSON.stringify(meta),
      };
    } else {
      connectorInput = {
        name: String(b.name).slice(0, 120),
        kind: 'generic',
        base_url: String(b.base_url).slice(0, 500),
        search_path: b.search_path
          ? String(b.search_path).slice(0, 200)
          : undefined,
        create_path: b.create_path
          ? String(b.create_path).slice(0, 200)
          : undefined,
        auth_type: ['bearer', 'header', 'none'].includes(b.auth_type)
          ? b.auth_type
          : 'bearer',
        auth_header: b.auth_header
          ? String(b.auth_header).slice(0, 80)
          : undefined,
        credential_enc: b.credential ? encrypt(String(b.credential)) : '',
        field_map_json: JSON.stringify(fieldMap),
      };
    }

    const connector = req.repo.createConnector(connectorInput);
    req.repo.audit('connector.created', {
      connectorId: connector.id,
      kind,
    });

    // Best-effort reachability/credential probe (does not block creation).
    // For vistage this actually authenticates against the API.
    const reach = await probe(connector);
    res.status(201).json({
      connector: publicConnector(connector),
      reachable: reach.ok,
      reachability_note: reach.ok ? undefined : reach.error,
    });
  })
);

// DELETE /api/connectors/:id — remove a connector this tenant owns.
// Its jobs and results cascade away with it (FK ON DELETE CASCADE).
router.delete(
  '/:id',
  asyncHandler(async (req, res) => {
    const connector = req.repo.getConnector(req.params.id);
    if (!connector) {
      return res.status(404).json({ error: 'Connector not found.' });
    }
    req.repo.deleteConnector(connector.id);
    req.repo.audit('connector.deleted', { connectorId: connector.id });
    res.json({ ok: true, deleted: connector.id });
  })
);

export default router;
