import secrets 
import pyotp 
import json 
from datetime import timedelta
from common.config.settings import get_settings

OTP_KEY_PREFIX = "otp:"

def _otp_redis_key(identifier: str) -> str:
    return f"{OTP_KEY_PREFIX}{identifier}"

async def create_sms_otp(redis, identifier: str) -> str:
    settings = get_settings()
    otp = "".join([ str(secrets.randbelow(10)) for _ in range(settings.otp_length)])

    payload = json.dumps({"otp": otp, "attempts": 0})
    await redis.setex(
        _otp_redis_key(identifier),
        timedelta(minutes=settings.otp_expire_minutes),
        payload,
    )
    return otp

async def verify_sms_otp(redis, identifier: str, submitted_otp: str):
    key = _otp_redis_key(identifier)
    raw = await redis.get(key)
    if not raw:
        return False
    
    data = json.loads(raw)
    attempts = data.get("attempts", 0)

    if attempts >= 3:
        await redis.delete(key)
        return False
    
    if data["otp"] != submitted_otp:
        data["attempts"] = attempts + 1
        ttl = await redis.ttl(key)
        if ttl > 0:
            await redis.setex(key, ttl, json.dumps(data))
        return False
    
    await redis.delete(key)
    return True

async def invalidate_otp(redis, identifier: str):
    await redis.delete(_otp_redis_key(identifier))


# TOTP (Authenticator App)
def generate_totp_secret() -> str:
    return pyotp.random_base32()

def get_totp_provisioning_uri(secret: str, user_email: str):
    settings = get_settings()
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=user_email, issuer_name=settings.totp_issuer)

def verify_totp(secret: str, submitted_code: str) -> bool:
    totp = pyotp.TOTP(secret)
    return totp.verify(submitted_code, valid_window=1)
