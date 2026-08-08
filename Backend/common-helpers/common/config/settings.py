from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "Pingora"
    app_env: str = "development"
    debug: bool = True

    supabase_url: str
    supabase_anon_key: str
    supabase_service_role_key: str

    jwt_secret_key: str
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7
    encrypt_jwt_payload: bool = True

    rsa_private_key_path: str = "./keys/private.pem"
    rsa_public_key_path: str = "./keys/public.pem"

    aes_secret_key: str

    redis_url: str = "redis://localhost:6379/0"

    csrf_secret_key: str
    csrf_token_expire_minutes: int = 60

    allowed_origins: str = "http://localhost:4000,http://localhost:5173"

    @property
    def allowed_origins_list(self):
        return [o.strip() for o in self.allowed_origins.split(",")]
    
    otp_expire_minutes: int = 5
    otp_length: int = 6
    totp_issuer: str = "Pingora"

    rate_limit_login_per_minute: int = 5
    rate_limit_otp_per_minute: int = 3


@lru_cache()
def get_settings():
    return Settings()