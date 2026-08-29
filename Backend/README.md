# Pingora Backend

FastAPI microservices behind an nginx gateway. This document covers getting the
stack running and the security decisions baked into it.

```
Backend/
├── common-helpers/          shared library, installed into every service
│   └── common/
│       ├── config/          settings, redis, supabase clients
│       ├── middleware/      security headers, rate limit, JWT, CSRF
│       ├── security/        password hashing, cookies, revocation store
│       └── utils/           crypto, jwt, csrf, otp
├── services/
│   ├── authentication/      login, logout, refresh, 2FA, sessions
│   └── administration/      admin API (verify-only)
├── gateway/                 nginx reverse proxy
├── migrations/              SQL schema
└── tests/                   security regression suite
```

## Getting started

### 1. Generate secrets

```bash
cd Backend
python scripts/generate_secrets.py --write
```

Writes `keys/private.pem` + `keys/public.pem` and seeds `.env` from
`.env.example`. Both are gitignored and excluded from the Docker build context.

Then fill in `SUPABASE_URL`, `SUPABASE_ANON_KEY` and
`SUPABASE_SERVICE_ROLE_KEY` in `.env`.

### 2. Create the database schema

Run `migrations/001_auth_schema.sql` in the Supabase SQL editor. It creates
`users` and `user_sessions`, and is safe to re-run.

If those tables already existed before you ran it, also run
`migrations/002_align_auth_schema.sql`. 001 creates its tables with
`create table if not exists`, so it silently does nothing to a table that is
already there -- any column added to 001 afterwards never reaches an existing
database, and the first symptom is a 500 on login (`42703: column
users.is_active does not exist`). 002 adds the missing columns, retypes
`expires_at`, and drops the legacy plaintext `refresh_token` column. It is
idempotent, so run it whenever a query fails on a column you can see in 001.

### 3. Run it

Full stack, reachable on `http://localhost`:

```bash
docker compose up --build
```

Or a single service for local iteration:

```bash
pip install -e common-helpers
pip install -r services/authentication/requirements.txt
cd services/authentication && python main.py     # :8000
```

### 4. Run the tests

```bash
pip install -r requirements-dev.txt
pytest
```

## Authentication flow

```
POST /auth/register      create account, send SMS OTP, return TOTP QR URI
POST /auth/login         password factor
POST /auth/verify-totp   second factor, consumes the MFA challenge
POST /auth/refresh       rotate the refresh token, mint a new access token
POST /auth/logout        revoke this session (or every session)
GET  /auth/me            current profile
GET  /auth/sessions      active sessions
DELETE /auth/sessions/{id}
```

With 2FA enabled, `/auth/login` returns `requires_totp: true` and a five-minute
`mfa_token` — **not** a user id. That distinction matters: handing back a bare
user id would let anyone brute-force TOTP codes against any account without ever
knowing the password.

## Security model

### Tokens

| | Lifetime | Storage | Notes |
|---|---|---|---|
| Access | 15 min | Browser memory | Never `localStorage` — anything in web storage is readable by injected script |
| Refresh | 7 days | HttpOnly cookie, `path=/auth` | Only an HMAC fingerprint is stored server-side |
| MFA challenge | 5 min | Response body | Single-use; burned on redemption |
| CSRF | 60 min | JS-readable cookie + body | HMAC-signed, bound to the session id |

The access token lives in memory only, so a page reload starts with none. The
`APP_INITIALIZER` in the Angular app silently exchanges the refresh cookie for a
fresh one before the first route resolves. The cost is one request on load; the
benefit is a bearer token that JavaScript cannot exfiltrate.

### Refresh rotation with reuse detection

Every refresh swaps the stored fingerprint for a new one, via a compare-and-swap
on the old value. If an already-rotated token comes back, it was replayed — so
the entire session family is revoked rather than just that token. Both the thief
and the legitimate user are signed out; the user can sign in again, the thief
cannot.

### CSRF

OWASP signed double-submit. The token is
`base64url(payload).base64url(HMAC-SHA256(payload))`, where the payload binds it
to one session id and carries its own expiry.

Binding to the session is what closes the classic double-submit hole: a
subdomain attacker who can set cookies still cannot mint a token carrying the
victim's session id. The token is not a secret — the same-origin policy stops a
cross-origin page from *reading* the cookie to copy into the header, which is
the whole mechanism.

### Payload encryption

A signed JWT is readable by anyone holding it. With `ENCRYPT_JWT_PAYLOAD=true`
the claim set is sealed with RSA-OAEP-SHA256 wrapping an AES-256-GCM content
key, and only routing metadata (`jti`, `exp`, `iss`, `aud`) stays in the clear
so intermediaries can still expire tokens without reading them.

The same envelope protects TOTP secrets at rest, so a database leak alone does
not yield working second factors.

TLS remains the primary transport protection; this is defence in depth for the
case where a token is logged, cached, or passes through an intermediary.

### Middleware order

Starlette wraps middleware in *reverse* registration order. The correct
execution order is:

```
CORS → SecurityHeaders → RequestContext → RateLimit → JWT → CSRF
```

CSRF must run **after** JWT, because it validates against the session id that
JWT puts on `request.state`. `register_middleware()` in
`common/middleware/auth_middleware.py` owns this ordering so individual services
cannot get it wrong.

### Other controls

- **Argon2id** password hashing, with transparent rehash when parameters change
- **Timing equalisation** — an unknown account still runs a verification against
  a dummy hash, so response time does not reveal whether an address exists
- **Account lockout** after 5 failed attempts, 15 minutes
- **Sliding-window rate limiting** in Redis, with unique members per hit (a
  timestamp-only member collapses same-second requests and undercounts badly)
- **Fail-open on Redis outage**, logged loudly — a cache outage must not lock
  every user out of the product
- **Non-root containers**, multi-stage builds, no compiler in the runtime image

## Going to production

`get_settings()` refuses to start if any of these is wrong when
`APP_ENV=production`:

- `DEBUG=false`
- `COOKIE_SECURE=true` (HTTPS only)
- `ALLOWED_ORIGINS` is an explicit list, never `*`

Also do these by hand:

- Mount `keys/` from a secret store. The service refuses to generate ephemeral
  keys in production — a fresh pair on restart invalidates every live token.
- Set `JWT_ALGORITHM=RS256` once a second service verifies tokens, so only the
  auth service holds the private key.
- Replace `_send_sms()` in `routes/auth_routes.py` with a real provider. It
  raises `NotImplementedError` in production rather than silently not sending.
- Terminate TLS at the gateway and set `COOKIE_SAMESITE=strict` if the SPA is
  same-origin.
- Schedule `purge_expired_sessions()` (pg_cron) to trim dead session rows.
