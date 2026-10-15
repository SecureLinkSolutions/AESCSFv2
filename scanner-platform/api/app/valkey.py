from functools import lru_cache

import redis

from app.config import get_settings


@lru_cache
def get_valkey() -> redis.Redis:
    # Valkey speaks the Redis protocol, so the redis client works unchanged.
    return redis.Redis.from_url(get_settings().valkey_url, decode_responses=True)
