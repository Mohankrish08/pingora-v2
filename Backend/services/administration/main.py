"""Administration service entrypoint.

A verify-only service: it never mints tokens, so it needs the RSA public key
alone. The shared middleware validates the bearer token that the authentication
service issued, which is the whole point of putting JWT verification in
common-helpers rather than duplicating it per service.
"""

from __future__ import annotations

import logging
import os
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse

from common.config.redis_client import get_redis_client
from common.config.settings import get_settings
from common.middleware.auth_middleware import register_middleware

logging.basicConfig(
    level=logging.DEBUG if get_settings().debug else logging.INFO,
    format="%(asctime)s %(levelname)-8s [%(name)s] %(message)s",
    stream=sys.stdout,
)

# basicConfig sets the level on the ROOT logger, which every third-party logger
# inherits. At DEBUG that turns the HTTP/2 stack underneath supabase-py into a
# firehose -- hpack alone logs a line per header field per request, burying our
# own output.
#
# It is also a disclosure risk, which is why these are pinned rather than left
# to taste: hpack logs header *values*, so a DEBUG run writes the Supabase
# service-role key and every bearer token into the log stream.
for _noisy in ("hpack", "h2", "httpcore", "urllib3", "websockets"):
    logging.getLogger(_noisy).setLevel(logging.WARNING)

# Kept at INFO: one useful "HTTP Request: POST ... 200 OK" line per outbound
# call, without the per-header noise from the layers below it.
logging.getLogger("httpx").setLevel(logging.INFO)

logger = logging.getLogger(__name__)


def require_role(request: Request, role: str) -> None:
    """Authorisation check on top of the middleware's authentication.

    The middleware proves *who* the caller is; role checks decide what they may
    do. Keeping them separate stops an authenticated non-admin from reaching
    admin routes just because the token verified.
    """
    roles = getattr(request.state, "roles", []) or []
    if role not in roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient privileges",
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    redis = get_redis_client()
    try:
        await redis.ping()
    except Exception:  # noqa: BLE001
        logger.error("Redis unavailable at startup", exc_info=True)

    logger.info("Administration service started in %s mode", settings.app_env)
    yield
    await redis.aclose()


def create_app() -> FastAPI:
    settings = get_settings()
    expose_docs = settings.debug and not settings.is_production

    app = FastAPI(
        title=f"{settings.app_name} Administration API",
        version="1.0.0",
        docs_url="/docs" if expose_docs else None,
        redoc_url="/redoc" if expose_docs else None,
        openapi_url="/openapi.json" if expose_docs else None,
        lifespan=lifespan,
    )

    register_middleware(app)

    @app.get("/health", tags=["Health"])
    async def health():
        return {"status": "ok", "service": "administration", "env": settings.app_env}

    @app.get("/health/ready", tags=["Health"])
    async def ready():
        try:
            await get_redis_client().ping()
        except Exception:  # noqa: BLE001
            return JSONResponse({"status": "degraded", "redis": False}, status_code=503)
        return {"status": "ok", "redis": True}

    @app.get("/whoami", tags=["Admin"])
    async def whoami(request: Request):
        """Smoke test that the shared JWT middleware is wired up correctly."""
        return {
            "user_id": getattr(request.state, "user_id", None),
            "email": getattr(request.state, "email", None),
            "roles": getattr(request.state, "roles", []),
            "session_id": getattr(request.state, "unique_session_id", None),
        }

    @app.get("/users", tags=["Admin"])
    async def list_users(request: Request):
        require_role(request, "admin")
        # Wire up to a repository when the admin feature set lands.
        return {"users": [], "message": "Not implemented yet"}

    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        request_id = getattr(request.state, "request_id", "unknown")
        logger.exception("Unhandled error", extra={"request_id": request_id})
        if settings.debug:
            raise exc
        return JSONResponse(
            {"detail": "Internal server error", "request_id": request_id},
            status_code=500,
        )

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    settings = get_settings()
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", "8001")),
        reload=settings.debug,
        log_level="debug" if settings.debug else "info",
        proxy_headers=settings.trust_proxy_headers,
    )
