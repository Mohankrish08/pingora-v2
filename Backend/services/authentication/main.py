import os 
import subprocess
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse


from common.config.settings import get_settings
from common.config.redis_client import get_redis_client
from common.middleware.auth_middleware import (
    JWTAuthMiddleware,
    CSRFMiddleware,
    RateLimitMiddleware
)

from routes.auth_routes import router as auth_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()

    private_key_path = settings.rsa_private_key_path
    public_key_path = settings.rsa_public_key_path
    os.makedirs(os.path.dirname(private_key_path), exist_ok=True)

    if not os.path.exists(private_key_path):
        print("Generating RSA-2048 key pair")
        subprocess.run(
            ["openssl", "genrsa", "-out", private_key_path, "2048"], check=True, capture_output=True
        )
        subprocess.run(
            ["openssl","rsa", "-in", private_key_path, "-pubout", "-out", public_key_path],
            check=True, capture_output=True
        )

    redis = get_redis_client()
    try:
        await redis.ping()
    except Exception as e:
        print(f"Redis unavailable: {e}")

    print(f"{settings.app_env} started [{settings.app_env}]")

    yield

    print("Redis connection closed")
    await redis.close()


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title=f"{settings.app_env} API",
        version="1.0.0",
        docs_url="/docs" if settings.debug else None,
        redoc_url="/redoc" if settings.debug else None,
        openapi_url="/openapi.json" if settings.debug else None,
        lifespan=lifespan
    )

    print("SETTINGS: ", settings.allowed_origins_list)


    app.add_middleware(JWTAuthMiddleware)
    app.add_middleware(CSRFMiddleware)
    app.add_middleware(RateLimitMiddleware)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*","X-CSRF-Token"],
        expose_headers=["X-CSRF-Token"]
    )

    app.include_router(auth_router, prefix="/auth")

    
    @app.get("/health", tags=["Health"])
    async def health():
        return {"status": "ok", "app": settings.app_name, "env": settings.app_env}
    
    @app.exception_handler(Exception)
    async def global_exception_handler(request, exc):
        if settings.debug:
            raise exc 
        return JSONResponse({"detail": "Internal server error"}, status_code=500)
    
    return app 

app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
    "main:app",
    host="0.0.0.0",
    port=8000,
    reload=get_settings().debug,
    log_level="debug" if get_settings().debug else "info"
    )