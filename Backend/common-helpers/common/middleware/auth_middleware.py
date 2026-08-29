"""Request-pipeline middleware: security headers, rate limiting, JWT, CSRF.

Ordering matters and is easy to get wrong. Starlette wraps middleware in
*reverse* registration order, so the last one added is the outermost. The
intended execution order is:

    CORS -> SecurityHeaders -> RequestContext -> RateLimit -> JWT -> CSRF

CSRF must run *after* JWT because it validates the token against the session id
that JWT puts on ``request.state``. Registering them the other way round makes
every state-changing request fail with 403. See ``register_middleware`` below,
which owns the order so individual services cannot get it wrong.
"""

from __future__ import annotations

import logging
import uuid

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from jose import ExpiredSignatureError, JWTError
from starlette.middleware.base import BaseHTTPMiddleware

from common.config.redis_client import get_redis_client
from common.config.settings import get_settings
from common.security.token_store import hit_rate_limit, is_revoked
from common.utils.csrf import validate_csrf_token
from common.utils.jwt_handler import decode_token

logger = logging.getLogger(__name__)

# Exact paths that need no access token. Prefix matching is deliberately NOT
# used: "/auth/login" as a prefix would also exempt "/auth/login-as-admin".
PUBLIC_ROUTES: set[str] = {
    "/auth/register",
    "/auth/login",
    "/auth/refresh",
    "/auth/verify-totp",
    "/auth/otp/send",
    "/auth/otp/verify",
    "/auth/password/forgot",
    "/auth/password/reset",
    "/health",
    "/health/ready",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/favicon.ico",
}

# Prefixes that are public in full (static asset trees).
PUBLIC_PREFIXES: tuple[str, ...] = ("/public/", "/static/")

CSRF_SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}


def _is_public(path: str) -> bool:
    return path in PUBLIC_ROUTES or path.startswith(PUBLIC_PREFIXES)


def client_ip(request: Request) -> str:
    """Real client IP, honouring ``X-Forwarded-For`` behind a trusted proxy.

    Only the *first* hop is taken, and only when we are configured to sit behind
    a proxy -- otherwise a client could spoof the header and bypass rate limits.
    """
    settings = get_settings()
    if settings.trust_proxy_headers:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()
    return request.client.host if request.client else "unknown"


# --- Security headers -----------------------------------------------------
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Baseline hardening headers on every response."""

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        settings = get_settings()

        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Permissions-Policy", "geolocation=(), microphone=(), camera=()"
        )
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.headers.setdefault("Cross-Origin-Resource-Policy", "same-site")

        # This is a JSON API: nothing should ever be rendered or framed.
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
        )

        if settings.is_production:
            response.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains; preload",
            )

        # Auth responses must never be cached by an intermediary.
        if request.url.path.startswith("/auth"):
            response.headers.setdefault("Cache-Control", "no-store, private")
            response.headers.setdefault("Pragma", "no-cache")

        return response


# --- Request context ------------------------------------------------------
class RequestContextMiddleware(BaseHTTPMiddleware):
    """Attach a correlation id so a request can be traced across services."""

    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex
        request.state.request_id = request_id

        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response


# --- Rate limiting --------------------------------------------------------
class RateLimitMiddleware(BaseHTTPMiddleware):
    """Sliding-window limits on the endpoints worth brute-forcing."""

    def _limits(self) -> dict[str, tuple[str, int, int]]:
        settings = get_settings()
        return {
            "/auth/login": ("login", settings.rate_limit_login_per_minute, 60),
            "/auth/register": ("register", settings.rate_limit_register_per_minute, 60),
            "/auth/verify-totp": ("otp", settings.rate_limit_otp_per_minute, 60),
            "/auth/otp/send": ("otp", settings.rate_limit_otp_per_minute, 60),
            "/auth/otp/verify": ("otp", settings.rate_limit_otp_per_minute, 60),
            "/auth/password/forgot": ("password", settings.rate_limit_otp_per_minute, 60),
            "/auth/refresh": ("refresh", settings.rate_limit_default_per_minute, 60),
        }

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.method == "OPTIONS":
            return await call_next(request)

        config = self._limits().get(request.url.path)
        if not config:
            return await call_next(request)

        bucket, limit, window = config
        allowed, retry_after = await hit_rate_limit(
            get_redis_client(), bucket, client_ip(request), limit, window
        )

        if not allowed:
            logger.warning(
                "Rate limit exceeded", extra={"bucket": bucket, "path": request.url.path}
            )
            return JSONResponse(
                {"detail": "Too many requests. Please try again later."},
                status_code=429,
                headers={"Retry-After": str(retry_after)},
            )

        return await call_next(request)


# --- JWT authentication ---------------------------------------------------
class JWTAuthMiddleware(BaseHTTPMiddleware):
    """Validate the bearer token and publish its claims on ``request.state``."""

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.method == "OPTIONS" or _is_public(request.url.path):
            return await call_next(request)

        auth_header = request.headers.get("Authorization", "")
        scheme, _, token = auth_header.partition(" ")

        if scheme.lower() != "bearer" or not token.strip():
            return JSONResponse(
                {"detail": "Missing or malformed authorization header"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )

        try:
            claims = decode_token(token.strip(), expected_type="access")
        except ExpiredSignatureError:
            return JSONResponse(
                {"detail": "Token has expired", "code": "token_expired"},
                status_code=401,
                headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
            )
        except JWTError:
            # The reason is logged, never returned: error detail is an oracle.
            logger.info("Rejected invalid access token", exc_info=True)
            return JSONResponse(
                {"detail": "Invalid token", "code": "token_invalid"},
                status_code=401,
                headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
            )

        # Revocation is checked against the decoded jti, not a prefix of the
        # raw token -- two different tokens can share a textual prefix.
        if await is_revoked(get_redis_client(), claims.get("jti"), claims.get("uid")):
            return JSONResponse(
                {"detail": "Token has been revoked", "code": "token_revoked"},
                status_code=401,
                headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
            )

        request.state.user_id = claims.get("sub")
        request.state.unique_session_id = claims.get("uid")
        request.state.email = claims.get("email")
        request.state.phone = claims.get("phone")
        request.state.display_name = claims.get("display_name")
        request.state.roles = claims.get("roles", [])
        request.state.jti = claims.get("jti")
        request.state.token_claims = claims

        return await call_next(request)


# --- CSRF -----------------------------------------------------------------
class CSRFMiddleware(BaseHTTPMiddleware):
    """Require a session-bound CSRF token on every state-changing request.

    Runs after JWT so ``request.state.unique_session_id`` is populated.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.method in CSRF_SAFE_METHODS or _is_public(request.url.path):
            return await call_next(request)

        settings = get_settings()
        header_token = request.headers.get(settings.csrf_header_name)

        if not header_token:
            return JSONResponse(
                {"detail": "Missing CSRF token", "code": "csrf_missing"},
                status_code=403,
            )

        session_id = getattr(request.state, "unique_session_id", None)
        if not session_id:
            return JSONResponse(
                {"detail": "CSRF validation failed", "code": "csrf_invalid"},
                status_code=403,
            )

        if not validate_csrf_token(header_token, session_id):
            logger.warning(
                "CSRF validation failed", extra={"path": request.url.path}
            )
            return JSONResponse(
                {"detail": "CSRF validation failed", "code": "csrf_invalid"},
                status_code=403,
            )

        return await call_next(request)


# --- Registration ---------------------------------------------------------
def register_middleware(app: FastAPI) -> None:
    """Install the stack in the one order that is correct.

    Registered innermost-first because Starlette applies them in reverse.
    """
    settings = get_settings()

    app.add_middleware(CSRFMiddleware)            # innermost: needs session id
    app.add_middleware(JWTAuthMiddleware)         # sets the session id
    app.add_middleware(RateLimitMiddleware)       # cheap rejection before crypto
    app.add_middleware(RequestContextMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)

    # Outermost, so preflights are answered without touching anything else.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=[
            "Authorization",
            "Content-Type",
            "Accept",
            settings.csrf_header_name,
            "X-Request-ID",
        ],
        expose_headers=[settings.csrf_header_name, "X-Request-ID", "Retry-After"],
        max_age=600,
    )
