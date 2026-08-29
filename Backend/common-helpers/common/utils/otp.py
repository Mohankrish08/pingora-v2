"""One-time passcodes: SMS OTP (Redis-backed) and TOTP (authenticator app)."""

from __future__ import annotations

import hmac
import json
import logging
import secrets
from datetime import timedelta

import pyotp

from common.config.settings import get_settings

logger = logging.getLogger(__name__)

OTP_KEY_PREFIX = "otp:"


def _otp_redis_key(identifier: str) -> str:
    return f"{OTP_KEY_PREFIX}{identifier}"


# --- SMS OTP --------------------------------------------------------------
async def create_sms_otp(redis, identifier: str) -> str:
    settings = get_settings()
    otp = "".join(str(secrets.randbelow(10)) for _ in range(settings.otp_length))

    payload = json.dumps({"otp": otp, "attempts": 0})
    await redis.setex(
        _otp_redis_key(identifier),
        timedelta(minutes=settings.otp_expire_minutes),
        payload,
    )
    return otp


async def verify_sms_otp(redis, identifier: str, submitted_otp: str) -> bool:
    settings = get_settings()
    key = _otp_redis_key(identifier)

    raw = await redis.get(key)
    if not raw:
        return False

    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        await redis.delete(key)
        return False

    attempts = int(data.get("attempts", 0))
    if attempts >= settings.otp_max_attempts:
        await redis.delete(key)
        return False

    if not hmac.compare_digest(str(data.get("otp", "")), submitted_otp):
        data["attempts"] = attempts + 1
        ttl = await redis.ttl(key)
        if ttl and ttl > 0:
            await redis.setex(key, ttl, json.dumps(data))
        return False

    # Single-use: delete on success so the code cannot be replayed.
    await redis.delete(key)
    return True


async def invalidate_otp(redis, identifier: str) -> None:
    await redis.delete(_otp_redis_key(identifier))


# --- TOTP (authenticator app) --------------------------------------------
def generate_totp_secret() -> str:
    return pyotp.random_base32()


def get_totp_provisioning_uri(secret: str, user_email: str) -> str:
    settings = get_settings()
    return pyotp.TOTP(secret).provisioning_uri(
        name=user_email, issuer_name=settings.totp_issuer
    )


def verify_totp(secret: str, submitted_code: str) -> bool:
    try:
        return pyotp.TOTP(secret).verify(submitted_code, valid_window=1)
    except Exception:  # noqa: BLE001
        logger.warning("TOTP verification error", exc_info=True)
        return False
