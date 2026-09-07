import logging

from django.conf import settings
from django.http import JsonResponse

from aegis_core.rate_limiter import TokenBucketRateLimiter
from aegis_core.request_meta import client_ip

from .decision import TIER_ATTACK, TIER_NORMAL, TIER_RISKY, DecisionEngine

logger = logging.getLogger(__name__)


class AdaptiveResponseMiddleware:
    """Applies the risk decision: rate limiting for everyone, a challenge
    response for the risky tier, a temporary ban for the attack tier.

    Runs in shadow mode by default (AEGIS_SHADOW_MODE=True): it still
    computes and logs every decision, but never blocks a request -- that
    lets the decision layer be validated against real traffic before it's
    trusted to actually affect responses. Placed after
    RequestTelemetryMiddleware so a blocked request is still logged with
    its real (403/429) status code.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self._decisions = DecisionEngine()
        self._rate_limiter = TokenBucketRateLimiter()

    def __call__(self, request):
        shadow_mode = settings.AEGIS_SHADOW_MODE
        ip_address = client_ip(request)

        if not shadow_mode and ip_address and self._decisions.is_banned(ip_address):
            self._log(ip_address, TIER_ATTACK, None, shadow_mode, blocked=True)
            return self._blocked_response("temporarily_blocked", None)

        decision = self._decisions.decide(
            ip_address=ip_address, path=request.path, query_params=request.GET
        )
        request.aegis_decision = decision

        blocked_response = None if shadow_mode else self._enforce(ip_address, decision)
        if decision.tier != TIER_NORMAL or blocked_response is not None:
            self._log(
                ip_address, decision.tier, decision.score, shadow_mode, blocked=blocked_response is not None
            )

        if blocked_response is not None:
            return blocked_response
        return self.get_response(request)

    def _enforce(self, ip_address, decision):
        if decision.tier == TIER_ATTACK:
            if ip_address:
                self._decisions.ban(ip_address)
            return self._blocked_response("temporarily_blocked", decision.score)

        if decision.tier == TIER_RISKY:
            return self._blocked_response("challenge_required", decision.score, status=403)

        if ip_address:
            rate_decision = self._rate_limiter.check_for_risk_score(f"ip:{ip_address}", decision.score)
            if not rate_decision.allowed:
                return self._blocked_response("rate_limited", decision.score, status=429)
        return None

    @staticmethod
    def _blocked_response(reason, score, *, status=403):
        payload = {"error": reason}
        if score is not None:
            payload["risk_score"] = score
        return JsonResponse(payload, status=status)

    @staticmethod
    def _log(ip_address, tier, score, shadow_mode, *, blocked):
        level = logging.WARNING if tier in (TIER_RISKY, TIER_ATTACK) else logging.INFO
        logger.log(
            level,
            "risk decision ip=%s tier=%s score=%s shadow=%s blocked=%s",
            ip_address,
            tier,
            "cached" if score is None else f"{score:.1f}",
            shadow_mode,
            blocked,
        )
