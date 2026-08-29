from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # App 
    app_name: str = "Pingora"
    app_env: Literal["development", "staging", "production"] = "development"
    debug: bool = False
    service_name: str = "authentication"

    #  Supabase 
    supabase_url: str
    supabase_anon_key: str
    supabase_service_role_key: str

    # JWT 
    jwt_secret_key: str
    jwt_algorithm: Literal["HS256", "HS384", "HS512", "RS256", "RS384", "RS512"] = "HS256"
    jwt_issuer: str = "pingora-auth"
    jwt_audience: str = "pingora-api"
    jwt_leeway_seconds: int = 10

    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7
    mfa_challenge_expire_minutes: int = 5

    # Hybrid RSA-OAEP + AES-256-GCM encryption of the JWT claim set.
    encrypt_jwt_payload: bool = True

    # Keys 
    rsa_private_key_path: str = "./keys/private.pem"
    rsa_public_key_path: str = "./keys/public.pem"

    # 32 raw bytes, base64-encoded.
    aes_secret_key: str

    #  Redis 
    redis_url: str = "redis://localhost:6379/0"

    # CSRF 
    csrf_secret_key: str
    csrf_token_expire_minutes: int = 60
    csrf_cookie_name: str = "XSRF-TOKEN"
    csrf_header_name: str = "X-CSRF-Token"

    # ─── Cookies ────────────────────────────────────────────────────────
    refresh_cookie_name: str = "refresh_token"
    refresh_cookie_path: str = "/auth"
    session_hint_cookie_name: str = "session_hint"
    cookie_secure: bool = False          # MUST be True in production (HTTPS only)
    cookie_samesite: Literal["lax", "strict", "none"] = "lax"
    cookie_domain: str | None = None

    # ─── CORS ───────────────────────────────────────────────────────────
    allowed_origins: str = "http://localhost:4200,http://localhost:4000"

    @property
    def allowed_origins_list(self) -> list[str]:
        return [o.strip() for o in self.allowed_origins.split(",") if o.strip()]

    # ─── OTP / 2FA ──────────────────────────────────────────────────────
    otp_expire_minutes: int = 5
    otp_length: int = 6
    otp_max_attempts: int = 3
    totp_issuer: str = "Pingora"

    # ─── Rate limiting ──────────────────────────────────────────────────
    rate_limit_login_per_minute: int = 5
    rate_limit_otp_per_minute: int = 3
    rate_limit_register_per_minute: int = 3
    rate_limit_default_per_minute: int = 120

    # Account lockout after repeated password failures.
    login_max_failed_attempts: int = 5
    login_lockout_minutes: int = 15

    # ─── Payload encryption (end-to-end, on top of TLS) ─────────────────
    # Off by default: TLS is the primary transport protection. Enable only
    # when an untrusted intermediary terminates TLS before your edge.
    encrypt_http_payload: bool = False

    # ─── Trusted proxies ────────────────────────────────────────────────
    # When behind nginx/ALB, the real client IP comes from X-Forwarded-For.
    trust_proxy_headers: bool = True

    @field_validator("aes_secret_key")
    @classmethod
    def _validate_aes_key(cls, v: str) -> str:
        import base64

        try:
            raw = base64.b64decode(v, validate=True)
        except Exception as exc:  # noqa: BLE001
            raise ValueError("AES_SECRET_KEY must be valid base64") from exc
        if len(raw) != 32:
            raise ValueError("AES_SECRET_KEY must decode to exactly 32 bytes (AES-256)")
        return v

    @field_validator("jwt_secret_key", "csrf_secret_key")
    @classmethod
    def _validate_secret_strength(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError("Secret keys must be at least 32 characters")
        return v

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @property
    def uses_asymmetric_jwt(self) -> bool:
        return self.jwt_algorithm.startswith("RS")


@lru_cache()
def get_settings() -> Settings:
    settings = Settings()

    # Fail fast on insecure production configuration.
    if settings.is_production:
        problems = []
        if settings.debug:
            problems.append("DEBUG must be false in production")
        if not settings.cookie_secure:
            problems.append("COOKIE_SECURE must be true in production")
        if "*" in settings.allowed_origins_list:
            problems.append("ALLOWED_ORIGINS must not be a wildcard in production")
        if problems:
            raise RuntimeError("Insecure production config: " + "; ".join(problems))

    return settings
