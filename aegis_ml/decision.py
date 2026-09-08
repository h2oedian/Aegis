import hashlib
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
from .serving import get_anomaly_model

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
    and reused only for matching request context until it expires. Each IP
    retains one cache entry, tagged with a digest of the scoring inputs, so
    a changed query, identity, or device cannot inherit a previous verdict.
    A confirmed attack-tier verdict
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

    def unban(self, identifier: str) -> None:
        """Manual override (e.g. from the dashboard). Also clears any
        cached decision, so the next request is scored fresh rather than
        possibly reusing a stale attack-tier verdict for a few more
        seconds until the decision cache's own TTL would have expired."""
        try:
            self._redis.delete(_ban_key(identifier), _decision_cache_key(identifier))
        except RedisError as exc:
            logger.warning("Could not clear ban: %s", exc)

    def _cached_decision(self, identifier: str, context: str) -> Decision | None:
        try:
            raw = self._redis.get(_decision_cache_key(identifier))
        except RedisError as exc:
            logger.warning("Decision cache unavailable, recomputing: %s", exc)
            return None
        if not raw:
            return None
        try:
            cached = json.loads(raw)
            if cached["context"] == context:
                return Decision(**cached["decision"])
        except (ValueError, TypeError, KeyError):
            # Old deployments stored an unqualified Decision. A cache miss
            # also safely handles incomplete or malformed entries.
            logger.debug("Ignoring an incompatible decision cache entry")
        return None

    def _cache_decision(self, identifier: str, decision: Decision, context: str) -> None:
        try:
            self._redis.set(
                _decision_cache_key(identifier),
                json.dumps({"context": context, "decision": asdict(decision)}),
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
        user_id: int | str | None = None,
        token_fingerprint: str | None = None,
        request_fingerprint: str | None = None,
        now: datetime | None = None,
    ) -> Decision:
        # QueryDict.items()/values() discard repeated query values. Include
        # every value in the digest without persisting raw request data.
        query_items = (
            list(query_params.lists())
            if hasattr(query_params, "lists")
            else list((query_params or {}).items())
        )
        context = hashlib.sha256(
            json.dumps(
                {
                    "path": path,
                    "query": sorted(query_items),
                    "user_id": user_id,
                    "token_fingerprint": token_fingerprint,
                    "request_fingerprint": request_fingerprint,
                    "rule_weight": self._rule_weight,
                    "now": now.isoformat() if now is not None else None,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        if ip_address:
            cached = self._cached_decision(ip_address, context)
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
        model = get_anomaly_model() if ip_address else None
        if model is None:
            # An unavailable model is not a benign model verdict. Preserve
            # the available rules' full weight and avoid unused DB queries.
            model_component = 0.0
            effective_rule_weight = 1.0
        else:
            model_component = model.score(extract_features(ip_address, now))
            effective_rule_weight = self._rule_weight
        score = combined_risk_score(
            rule_result.score, model_component, rule_weight=effective_rule_weight
        )

        decision = Decision(
            score=score,
            tier=classify_score(score),
            rule_score=rule_result.score,
            model_score=model_component,
        )
        if ip_address:
            self._cache_decision(ip_address, decision, context)
        return decision
