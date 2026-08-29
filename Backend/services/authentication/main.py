"""Authentication service entrypoint."""

from __future__ import annotations

import logging
import os
import sys
from contextlib import asynccontextmanager

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from common.config.redis_client import get_redis_client
from common.config.settings import get_settings
from common.middleware.auth_middleware import register_middleware
from common.security.cookies import SessionEndedError, clear_auth_cookies
from routes.auth_routes import router as auth_router

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


def ensure_rsa_keypair() -> None:
    settings = get_settings()
    private_path = settings.rsa_private_key_path
    public_path = settings.rsa_public_key_path

    if os.path.exists(private_path) and os.path.exists(public_path):
        return

    if settings.is_production:
        raise RuntimeError(
            f"RSA keys missing at {private_path}. Mount them from your secret "
            "store; refusing to generate ephemeral keys in production."
        )

    logger.warning("RSA key pair not found -- generating a development pair")

    for path in (private_path, public_path):
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    with open(private_path, "wb") as fh:
        fh.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    try:
        os.chmod(private_path, 0o600)
    except OSError:
        pass  # Windows and some mounts do not support POSIX modes.

    with open(public_path, "wb") as fh:
        fh.write(
            private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    ensure_rsa_keypair()

    redis = get_redis_client()
    try:
        await redis.ping()
        logger.info("Redis connection established")
    except Exception:  # noqa: BLE001
        logger.error("Redis unavailable at startup", exc_info=True)

    logger.info("%s service started in %s mode", settings.app_name, settings.app_env)

    yield

    await redis.aclose()
    logger.info("Redis connection closed")


def create_app() -> FastAPI:
    settings = get_settings()
    expose_docs = settings.debug and not settings.is_production

    app = FastAPI(
        title=f"{settings.app_name} Authentication API",
        version="1.0.0",
        docs_url="/docs" if expose_docs else None,
        redoc_url="/redoc" if expose_docs else None,
        openapi_url="/openapi.json" if expose_docs else None,
        lifespan=lifespan,
    )

    register_middleware(app)
    app.include_router(auth_router, prefix="/auth")

    @app.get("/health", tags=["Health"])
    async def health():
        return {"status": "ok", "service": settings.service_name, "env": settings.app_env}

    @app.get("/health/ready", tags=["Health"])
    async def ready():
        """Readiness probe: reports dependency health without failing the pod."""
        redis_ok = True
        try:
            await get_redis_client().ping()
        except Exception:  # noqa: BLE001
            redis_ok = False

        return JSONResponse(
            {"status": "ok" if redis_ok else "degraded", "redis": redis_ok},
            status_code=200 if redis_ok else 503,
        )

    @app.exception_handler(SessionEndedError)
    async def session_ended_handler(request: Request, exc: SessionEndedError):
        response = JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
        clear_auth_cookies(response)
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_handler(request: Request, exc: RequestValidationError):
        errors = [
            {"field": ".".join(str(p) for p in err["loc"][1:]), "message": err["msg"]}
            for err in exc.errors()
        ]
        return JSONResponse(
            {"detail": "Validation failed", "errors": errors}, status_code=422
        )

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
        port=int(os.getenv("PORT", "8000")),
        reload=settings.debug,
        log_level="debug" if settings.debug else "info",
        proxy_headers=settings.trust_proxy_headers,
        forwarded_allow_ips="*" if settings.trust_proxy_headers else None,
    )
