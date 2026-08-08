import time
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from jose import JWTError, ExpiredSignatureError

from common.utils.jwt_handler import decode_token
from common.utils.csrf import validate_csrf_token
from common.config.redis_client import get_redis_client
from common.config.settings import get_settings

PUBLIC_ROUTES = {
    "/auth/login",
    "/auth/register",
    "/auth/refresh",
    "/auth/otp/send",
    "/auth/otp/verify",
    "/auth/password/forgot",
    "/health",
    "/docs",
    "/openapi.json",
    "/pingora-icon",
    "/redoc"
}

CSRF_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

CSRF_PROTECTED_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# --- JWT Auth Middleware ---
class JWTAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path

        body = await request.body()
        print(body.decode("utf-8"))

        if request.method == "OPTIONS":
            return await call_next(request)

        if any(path.startswith(pub) for pub in PUBLIC_ROUTES):
            return await call_next(request)
        
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer"):
            return JSONResponse({"detail": "Missing authorization token"}, status_code=401)
        
        token = auth_header.split(" ", 1)[1]
        redis = get_redis_client()

        try:
            
            is_blacklisted = await redis.exists(f"blacklist:jti:{token[:32]}")
            if is_blacklisted:
                return JSONResponse({"detail": "Token has been revoked"}, status_code=401)
            
            claims = decode_token(token)

            if claims.get("type") != "access":
                return JSONResponse({"detail": "Invalid token type"}, status_code=401)
            
            request.state.user_id            = claims["sub"]
            request.state.unique_session_id  = claims["uid"]
            request.state.email              = claims.get("email")
            request.state.phone              = claims.get("phone")
            request.state.display_name       = claims.get("display")
            request.state.jti                = claims.get("jti")

        except ExpiredSignatureError:
            return JSONResponse({"detail": "Token has expired"}, status_code=401)
        except JWTError as e:
            return JSONResponse({"detail": f"Token is invalid: {e}"}, status_code=401)
        
        return await call_next(request)
    

# --- CSRF Middleware
class CSRFMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path
        method = request.method
        print("Method: ", method)

        print("CSRF: ", request)

        if method in CSRF_SAFE_METHODS:
            return await call_next(request)
        
        if any(path.startswith(pub) for pub in PUBLIC_ROUTES):
            return await call_next(request)

        csrf_header = request.headers.get("X-CSRF-Token")
        if not csrf_header:
            return JSONResponse({"detail": "Missing CSRF Token"}, status_code=403)
        
        uid = getattr(request.state, "unique_session_id", None)
        if not uid:
            return JSONResponse({"detail": "CSRF validation failed"}, status_code=403)
        
        if not validate_csrf_token(csrf_header, uid):
            return JSONResponse({"detail": "CSRF validation failed"}, status_code=403)
        
        return await call_next(request)
    
# --- Rate Limit Middleware ---
class RateLimitMiddleware(BaseHTTPMiddleware):
    LIMITS = {
        "/auth/login": ("login", 5, 60),
        "/auth/otp/send": ("otp", 3, 60),
        "/auth/otp/verify": ("otp", 5, 60)
    }

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path
        config = self.LIMITS.get(path)

        if not config:
            return await call_next(request)
        
        label, limit, window = config
        ip = request.client.host
        key = f"ratelimit:{label}:{ip}"
        redis = get_redis_client()

        now = int(time.time())
        pipe = redis.pipeline()
        pipe.zadd(key, {str(now): now})
        pipe.zremrangebyscore(key, 0, now - window)
        pipe.zcard(key)
        pipe.expire(key, window)
        results = await pipe.execute()
        count = results[2]

        if count > limit:
            retry_after = window
            return JSONResponse(
                {"detail": f"Too many requests. Retry after {retry_after}s",},
                status_code=429,
                headers={"Retry_After": str(retry_after)},
            )
        return await call_next(request)






    