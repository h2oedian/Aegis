from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from django.utils import timezone

from .base import RuleResult
from .rules import not_found_rate_rule, sequential_id_scan_rule, unauthorized_attempts_rule
from .signatures import scan_injection_signatures


@dataclass(frozen=True)
class RuleEngineResult:
    score: float
    results: list[RuleResult] = field(default_factory=list)

    @property
    def triggered_rules(self) -> list[RuleResult]:
        return [result for result in self.results if result.triggered]


class RuleEngine:
    """Combines stateless signature checks with stateful, windowed rules.

    Signature matching (SQLi/XSS/path traversal) is evaluated inline against
    the current request; the others look at that IP's recent RequestLog
    history, which is why they need a database round trip and a client IP.
    """

    def __init__(
        self,
        *,
        window: timedelta = timedelta(minutes=5),
        unauthorized_threshold: int = 5,
        not_found_rate_threshold: float = 0.3,
        sequential_run_threshold: int = 3,
    ) -> None:
        self.window = window
        self.unauthorized_threshold = unauthorized_threshold
        self.not_found_rate_threshold = not_found_rate_threshold
        self.sequential_run_threshold = sequential_run_threshold

    def evaluate(
        self,
        *,
        ip_address: str | None,
        path: str,
        query_params: Mapping[str, str] | None = None,
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
        ]
        score = min(100.0, sum(result.score for result in results))
        return RuleEngineResult(score=score, results=results)
