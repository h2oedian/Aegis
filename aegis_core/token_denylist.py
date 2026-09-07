import logging

from django.conf import settings
from redis.exceptions import RedisError

from .models import RefreshTokenRecord
from .redis_client import get_redis_client

logger = logging.getLogger(__name__)


def _jti_key(jti: str) -> str:
    return f"aegis:denylist:jti:{jti}"


def _family_key(family_id: str) -> str:
    return f"aegis:denylist:family:{family_id}"


def deny_jti(jti: str, *, ttl_seconds: int | None = None) -> None:
    ttl = settings.AEGIS_REFRESH_TOKEN_LIFETIME_SECONDS if ttl_seconds is None else ttl_seconds
    try:
        get_redis_client().set(_jti_key(jti), "1", ex=max(1, int(ttl)))
    except RedisError as exc:
        logger.warning("Could not add jti to denylist (DB record is still authoritative): %s", exc)


def deny_family(family_id: str, *, ttl_seconds: int | None = None) -> None:
    ttl = settings.AEGIS_REFRESH_TOKEN_LIFETIME_SECONDS if ttl_seconds is None else ttl_seconds
    try:
        get_redis_client().set(_family_key(family_id), "1", ex=max(1, int(ttl)))
    except RedisError as exc:
        logger.warning("Could not add family to denylist (DB record is still authoritative): %s", exc)


def is_jti_denied(jti: str) -> bool:
    """Fast Redis check only -- the durable record for a specific refresh
    token is RefreshTokenRecord.used_at/revoked_at, checked separately."""
    try:
        return bool(get_redis_client().exists(_jti_key(jti)))
    except RedisError as exc:
        logger.warning("Denylist unavailable, treating jti as not denied: %s", exc)
        return False


def is_family_revoked(family_id: str) -> bool:
    """Whether every token in this family should be rejected -- checked on
    every authenticated request, so this is deliberately not fail-open:
    revocation is a security boundary, not just an availability nicety.
    Redis is a cache in front of it; RefreshTokenRecord is authoritative.
    """
    try:
        return bool(get_redis_client().exists(_family_key(family_id)))
    except RedisError as exc:
        logger.warning("Family denylist cache unavailable, falling back to the database: %s", exc)
    return RefreshTokenRecord.objects.filter(family_id=family_id, revoked_at__isnull=False).exists()
