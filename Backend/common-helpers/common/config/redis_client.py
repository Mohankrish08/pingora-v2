from functools import lru_cache
import redis.asyncio as redis
from common.config.settings import get_settings

@lru_cache()
def get_redis_client():
    settings = get_settings()
    return redis.from_url(
        settings.redis_url,
        encoding="utf-8",
        decode_responses=True,
    )