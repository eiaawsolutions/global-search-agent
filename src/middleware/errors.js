// Error handling + 404. Centralized so no route leaks a stack trace.
import { config } from '../config.js';

export function notFound(req, res) {
  res.status(404).json({ error: 'Not found.' });
}

// Express error middleware (4-arg signature is required).
// In production the client only ever sees a safe message; the detail is
// logged server-side.
export function errorHandler(err, req, res, next) {
  // Body-parser / JSON syntax errors → 400, not 500.
  const isBadJson = err.type === 'entity.parse.failed' || err instanceof SyntaxError;
  const status = isBadJson ? 400 : err.status || err.statusCode || 500;

  if (status >= 500) {
    console.error(`[error] ${req.method} ${req.path}:`, err.message);
    if (!config.isProd) console.error(err.stack);
  }

  const message =
    status >= 500
      ? config.isProd
        ? 'Internal server error.'
        : err.message
      : err.message || 'Bad request.';

  res.status(status).json({ error: message });
}
