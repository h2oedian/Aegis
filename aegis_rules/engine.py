from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from django.utils import timezone

from aegis_core.geoip import locate_ip

from .base import RuleResult
from .rules import (
    device_fingerprint_rule,
    impossible_travel_rule,
    not_found_rate_rule,
    sequential_id_scan_rule,
    unauthorized_attempts_rule,
)
from .signatures import scan_injection_signatures


@dataclass(frozen=True)
class RuleEngineResult:
    score: float
    results: list[RuleResult] = field(default_factory=list)

    @property
    def triggered_rules(self) -> list[RuleResult]:
        return [result for result in self.results if result.triggered]


class RuleEngine:
    """Combines stateless signature/fingerprint checks with stateful,
    windowed rules.

    Signature and device-fingerprint matching are evaluated inline against
    the current request; the IP-windowed rules look at that IP's recent
    RequestLog history, and the travel rule looks at that user's, which is
    why they need a database round trip and, respectively, a client IP or
    an authenticated user id.
    """

    def __init__(
        self,
        *,
        window: timedelta = timedelta(minutes=5),
        unauthorized_threshold: int = 5,
        not_found_rate_threshold: float = 0.3,
        sequential_run_threshold: int = 3,
        travel_window: timedelta = timedelta(hours=6),
        max_plausible_speed_kmh: float = 900.0,
        locate=locate_ip,
    ) -> None:
        self.window = window
        self.unauthorized_threshold = unauthorized_threshold
        self.not_found_rate_threshold = not_found_rate_threshold
        self.sequential_run_threshold = sequential_run_threshold
        self.travel_window = travel_window
        self.max_plausible_speed_kmh = max_plausible_speed_kmh
        self.locate = locate

    def evaluate(
        self,
        *,
        ip_address: str | None,
        path: str,
        query_params: Mapping[str, str] | None = None,
        user_id: int | None = None,
        token_fingerprint: str | None = None,
        request_fingerprint: str | None = None,
        now: datetime | None = None,
    ) -> RuleEngineResult:
        now = now or timezone.now()
        results = [
            scan_injection_signatures(path, query_params or {}),
            unauthorized_attempts_rule(
                ip_address, now, window=self.window, threshold=self.unauthorized_threshold
            ),
            not_found_rate_rule(
                ip_address,
                now,
                window=self.window,
                rate_threshold=self.not_found_rate_threshold,
            ),
            sequential_id_scan_rule(
                ip_address,
                now,
                window=self.window,
                run_threshold=self.sequential_run_threshold,
            ),
            impossible_travel_rule(
                user_id,
                ip_address,
                now,
                window=self.travel_window,
                max_plausible_speed_kmh=self.max_plausible_speed_kmh,
                locate=self.locate,
            ),
            device_fingerprint_rule(token_fingerprint, request_fingerprint),
        ]
        score = min(100.0, sum(result.score for result in results))
        return RuleEngineResult(score=score, results=results)
