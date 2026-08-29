"""Redis-backed revocation, lockout and rate-limit state.

JWTs are stateless, which is exactly why logout needs help: the signature stays
valid until ``exp``. We keep two short-lived deny lists instead of a session
table lookup on every request:

``blacklist:jti:<jti>``      -- one revoked access token (logout on one device)
``blacklist:session:<sid>``  -- an entire session family (logout everywhere,
                                or refresh-token reuse detected)

Every key carries a TTL equal to the remaining lifetime of what it revokes, so
the deny list can never grow without bound.
"""

from __future__ import annotations

import logging
import time
import uuid

logger = logging.getLogger(__name__)

JTI_PREFIX = "blacklist:jti:"
SESSION_PREFIX = "blacklist:session:"
LOCKOUT_PREFIX = "lockout:"
FAILED_PREFIX = "failed:"
RATELIMIT_PREFIX = "ratelimit:"


# --- Revocation -----------------------------------------------------------
async def revoke_token(redis, jti: str, ttl_seconds: int) -> None:
    if ttl_seconds <= 0:
        return
    await redis.setex(f"{JTI_PREFIX}{jti}", ttl_seconds, "1")


async def revoke_session(redis, session_id: str, ttl_seconds: int) -> None:
    if ttl_seconds <= 0:
        return
    await redis.setex(f"{SESSION_PREFIX}{session_id}", ttl_seconds, "1")


async def is_revoked(redis, jti: str | None, session_id: str | None) -> bool:
    keys = []
    if jti:
        keys.append(f"{JTI_PREFIX}{jti}")
    if session_id:
        keys.append(f"{SESSION_PREFIX}{session_id}")
    if not keys:
        return False

    try:
        values = await redis.mget(keys)
    except Exception:  # noqa: BLE001
        logger.error("Revocation check unavailable; allowing request", exc_info=True)
        return False

    return any(v is not None for v in values)


# --- Account lockout ------------------------------------------------------
async def register_failed_login(
    redis, identifier: str, max_attempts: int, lockout_minutes: int
) -> int:
    """Count a failed password attempt and lock the account at the threshold.

    Returns the running failure count.
    """
    key = f"{FAILED_PREFIX}{identifier}"
    try:
        count = await redis.incr(key)
        if count == 1:
            await redis.expire(key, lockout_minutes * 60)
        if count >= max_attempts:
            await redis.setex(f"{LOCKOUT_PREFIX}{identifier}", lockout_minutes * 60, "1")
        return int(count)
    except Exception:  # noqa: BLE001
        logger.error("Could not record failed login", exc_info=True)
        return 0


async def clear_failed_logins(redis, identifier: str) -> None:
    try:
        await redis.delete(f"{FAILED_PREFIX}{identifier}", f"{LOCKOUT_PREFIX}{identifier}")
    except Exception:  # noqa: BLE001
        logger.error("Could not clear failed logins", exc_info=True)


async def lockout_seconds_remaining(redis, identifier: str) -> int:
    try:
        ttl = await redis.ttl(f"{LOCKOUT_PREFIX}{identifier}")
    except Exception:  # noqa: BLE001
        logger.error("Could not read lockout state", exc_info=True)
        return 0
    return ttl if ttl and ttl > 0 else 0


# --- Sliding-window rate limiting -----------------------------------------
async def hit_rate_limit(
    redis, bucket: str, identifier: str, limit: int, window_seconds: int
) -> tuple[bool, int]:
    key = f"{RATELIMIT_PREFIX}{bucket}:{identifier}"
    now = time.time()
    member = f"{now}:{uuid.uuid4().hex}"

    try:
        pipe = redis.pipeline()
        pipe.zremrangebyscore(key, 0, now - window_seconds)
        pipe.zadd(key, {member: now})
        pipe.zcard(key)
        pipe.expire(key, window_seconds)
        results = await pipe.execute()
        count = int(results[2])
    except Exception:  # noqa: BLE001
        logger.error("Rate limiter unavailable; allowing request", exc_info=True)
        return True, 0

    if count > limit:
        return False, window_seconds

    return True, 0
