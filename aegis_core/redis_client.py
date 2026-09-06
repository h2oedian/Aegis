from functools import lru_cache

from django.conf import settings
from redis import Redis


@lru_cache(maxsize=1)
def get_redis_client():
    return Redis.from_url(
        settings.REDIS_URL,
        decode_responses=True,
        socket_connect_timeout=settings.AEGIS_REDIS_SOCKET_TIMEOUT_SECONDS,
        socket_timeout=settings.AEGIS_REDIS_SOCKET_TIMEOUT_SECONDS,
        retry_on_timeout=False,
    )
