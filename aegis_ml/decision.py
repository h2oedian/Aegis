import json
import logging
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import datetime

from django.conf import settings
from django.utils import timezone
from redis.exceptions import RedisError

from aegis_core.redis_client import get_redis_client
from aegis_rules.engine import RuleEngine

from .features import extract_features
from .risk import combined_risk_score
from .serving import model_score

logger = logging.getLogger(__name__)

TIER_NORMAL = "normal"
TIER_SUSPICIOUS = "suspicious"
TIER_RISKY = "risky"
TIER_ATTACK = "attack"


def classify_score(score: float) -> str:
    """Map a 0-100 combined score to the roadmap's four response tiers."""
    if score >= 80:
        return TIER_ATTACK
    if score >= 60:
        return TIER_RISKY
    if score >= 30:
        return TIER_SUSPICIOUS
    return TIER_NORMAL


@dataclass(frozen=True)
class Decision:
    score: float
    tier: str
    rule_score: float
    model_score: float

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @classmethod
    def from_json(cls, raw: str) -> "Decision":
        return cls(**json.loads(raw))


def _decision_cache_key(identifier: str) -> str:
    return f"aegis:decision:{identifier}"


def _ban_key(identifier: str) -> str:
    return f"aegis:ban:{identifier}"


class DecisionEngine:
    """Combines the rule engine and anomaly model into one cached decision.

    Rule evaluation hits Postgres and model scoring runs a scikit-learn
    estimator -- too slow to redo on every request from the same client, so
    the result is cached in Redis under a short TTL (AEGIS_DECISION_CACHE_TTL_SECONDS)
    and reused for that IP until it expires. A confirmed attack-tier verdict
    is remembered separately and longer (AEGIS_BAN_DURATION_SECONDS), so a
    banned IP is rejected without recomputing anything at all.
    """

    def __init__(
        self,
        *,
        engine: RuleEngine | None = None,
        rule_weight: float | None = None,
        redis_client=None,
    ) -> None:
        self._engine = engine or RuleEngine()
        self._rule_weight = settings.AEGIS_RULE_WEIGHT if rule_weight is None else rule_weight
        self._redis = redis_client or get_redis_client()

    def is_banned(self, identifier: str) -> bool:
        try:
            return bool(self._redis.exists(_ban_key(identifier)))
        except RedisError as exc:
            logger.warning("Ban cache unavailable, treating as not banned: %s", exc)
            return False

    def ban(self, identifier: str) -> None:
        try:
            self._redis.set(_ban_key(identifier), "1", ex=int(settings.AEGIS_BAN_DURATION_SECONDS))
        except RedisError as exc:
            logger.warning("Could not record ban: %s", exc)

    def _cached_decision(self, identifier: str) -> Decision | None:
        try:
            raw = self._redis.get(_decision_cache_key(identifier))
        except RedisError as exc:
            logger.warning("Decision cache unavailable, recomputing: %s", exc)
            return None
        return Decision.from_json(raw) if raw else None

    def _cache_decision(self, identifier: str, decision: Decision) -> None:
        try:
            self._redis.set(
                _decision_cache_key(identifier),
                decision.to_json(),
                ex=max(1, int(settings.AEGIS_DECISION_CACHE_TTL_SECONDS)),
            )
        except RedisError as exc:
            logger.warning("Could not cache decision: %s", exc)

    def decide(
        self,
        *,
        ip_address: str | None,
        path: str,
        query_params: Mapping[str, str] | None = None,
        user_id: int | None = None,
        token_fingerprint: str | None = None,
        request_fingerprint: str | None = None,
        now: datetime | None = None,
    ) -> Decision:
        if ip_address:
            cached = self._cached_decision(ip_address)
            if cached is not None:
                return cached

        now = now or timezone.now()
        rule_result = self._engine.evaluate(
            ip_address=ip_address,
            path=path,
            query_params=query_params,
            user_id=user_id,
            token_fingerprint=token_fingerprint,
            request_fingerprint=request_fingerprint,
            now=now,
        )
        features = extract_features(ip_address, now) if ip_address else {}
        model_component = model_score(features) if ip_address else 0.0
        score = combined_risk_score(rule_result.score, model_component, rule_weight=self._rule_weight)

        decision = Decision(
            score=score,
            tier=classify_score(score),
            rule_score=rule_result.score,
            model_score=model_component,
        )
        if ip_address:
            self._cache_decision(ip_address, decision)
        return decision
