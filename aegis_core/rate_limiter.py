import logging
import math
import time
from dataclasses import dataclass
from pathlib import Path

from django.conf import settings
from redis.exceptions import RedisError

from .redis_client import get_redis_client

logger = logging.getLogger(__name__)

_TOKEN_BUCKET_SCRIPT = (Path(__file__).parent / "scripts" / "token_bucket.lua").read_text()


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    remaining_tokens: float
    capacity: float


def bucket_params_for_score(
    score: float,
    *,
    base_capacity: float | None = None,
    base_refill_per_second: float | None = None,
    min_capacity: float | None = None,
    min_refill_per_second: float | None = None,
) -> tuple[float, float]:
    """Shrink the bucket as the risk score rises: 0 -> full rate, 100 -> a trickle."""
    base_capacity = settings.AEGIS_RATE_LIMIT_BASE_CAPACITY if base_capacity is None else base_capacity
    base_refill_per_second = (
        settings.AEGIS_RATE_LIMIT_BASE_REFILL_PER_SECOND
        if base_refill_per_second is None
        else base_refill_per_second
    )
    min_capacity = settings.AEGIS_RATE_LIMIT_MIN_CAPACITY if min_capacity is None else min_capacity
    min_refill_per_second = (
        settings.AEGIS_RATE_LIMIT_MIN_REFILL_PER_SECOND
        if min_refill_per_second is None
        else min_refill_per_second
    )

    score = max(0.0, min(100.0, score))
    factor = 1.0 - (score / 100.0) * 0.95
    capacity = max(min_capacity, base_capacity * factor)
    refill_rate = max(min_refill_per_second, base_refill_per_second * factor)
    return capacity, refill_rate


class TokenBucketRateLimiter:
    """An atomic Redis+Lua token bucket, fail-open if Redis is unavailable.

    The read-refill-decrement-write sequence runs as one Lua script so two
    concurrent requests against the same key can't both read stale tokens
    and both be allowed through.
    """

    def __init__(self, redis_client=None, key_prefix: str = "aegis:ratelimit:"):
        self._redis = redis_client or get_redis_client()
        self._key_prefix = key_prefix
        self._script = self._redis.register_script(_TOKEN_BUCKET_SCRIPT)

    def check(
        self,
        identifier: str,
        *,
        capacity: float,
        refill_rate: float,
        cost: float = 1.0,
        now: float | None = None,
    ) -> RateLimitDecision:
        now = time.time() if now is None else now
        ttl_seconds = max(1, math.ceil((capacity / refill_rate) * 2))
        try:
            allowed, remaining = self._script(
                keys=[f"{self._key_prefix}{identifier}"],
                args=[capacity, refill_rate, now, cost, ttl_seconds],
            )
        except RedisError as exc:
            # Rate limiting is fail-open, the same tradeoff already made for
            # request telemetry: an unavailable Redis must not take the
            # protected API down with it.
            logger.warning("Rate limiter unavailable, failing open: %s", exc)
            return RateLimitDecision(allowed=True, remaining_tokens=capacity, capacity=capacity)
        return RateLimitDecision(
            allowed=bool(int(allowed)), remaining_tokens=float(remaining), capacity=capacity
        )

    def check_for_risk_score(
        self, identifier: str, score: float, *, cost: float = 1.0, now: float | None = None
    ) -> RateLimitDecision:
        capacity, refill_rate = bucket_params_for_score(score)
        return self.check(identifier, capacity=capacity, refill_rate=refill_rate, cost=cost, now=now)
