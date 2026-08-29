export const environment = {
  production: false,

  // Point these at the nginx gateway (http://localhost) once you run the full
  // docker compose stack; the direct ports are for `uvicorn main:app` locally.
  authAPI: 'http://localhost:8000',
  adminAPI: 'http://localhost:8001',

  apiTimeout: 30000,

  jwtPayloadEncrypted: true,

  csrfCookieName: 'XSRF-TOKEN',
  csrfHeaderName: 'X-CSRF-Token',

  sessionHintCookieName: 'session_hint',
};
