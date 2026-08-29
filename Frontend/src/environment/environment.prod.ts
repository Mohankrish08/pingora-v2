export const environment = {
  production: true,

  // Same-origin in production: the SPA and the API sit behind one gateway, so
  // cookies are first-party and SameSite=strict stays workable.
  authAPI: '/api',
  adminAPI: '/api/admin',

  apiTimeout: 30000,
  jwtPayloadEncrypted: true,

  csrfCookieName: 'XSRF-TOKEN',
  csrfHeaderName: 'X-CSRF-Token',

  // Non-secret flag the server sets alongside the HttpOnly refresh cookie, so
  // the SPA can tell a returning visitor from an anonymous one without a round
  // trip. Must match SESSION_HINT_COOKIE_NAME in Backend/.env.
  sessionHintCookieName: 'session_hint',
};
