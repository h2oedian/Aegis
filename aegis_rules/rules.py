import re
from datetime import datetime, timedelta

from aegis_core.models import RequestLog
from aegis_core.paths import normalize_path

from .base import RuleResult

_TRAILING_ID_PATTERN = re.compile(r"\d+")


def _scale(count: float, threshold: float, *, cap: float = 100.0, midpoint: float = 50.0) -> float:
    """Linearly scale ``count`` so it reaches ``midpoint`` at ``threshold``."""
    if count <= 0 or threshold <= 0:
        return 0.0
    return min(cap, (count / threshold) * midpoint)


def unauthorized_attempts_rule(
    ip_address: str | None,
    now: datetime,
    *,
    window: timedelta = timedelta(minutes=5),
    threshold: int = 5,
) -> RuleResult:
    """Score repeated 401s from one IP within ``window`` (credential probing)."""
    if not ip_address:
        return RuleResult("unauthorized_attempts", 0.0, False, "no client ip")

    count = RequestLog.objects.filter(
        ip_address=ip_address,
        status_code=401,
        created_at__gte=now - window,
        created_at__lte=now,
    ).count()
    return RuleResult(
        rule="unauthorized_attempts",
        score=_scale(count, threshold),
        triggered=count >= threshold,
        detail=f"{count} x 401 in the last {int(window.total_seconds())}s",
    )


def not_found_rate_rule(
    ip_address: str | None,
    now: datetime,
    *,
    window: timedelta = timedelta(minutes=5),
    rate_threshold: float = 0.3,
    min_requests: int = 5,
) -> RuleResult:
    """Score a high share of 404s from one IP within ``window`` (scraping/enum)."""
    if not ip_address:
        return RuleResult("not_found_rate", 0.0, False, "no client ip")

    recent = RequestLog.objects.filter(
        ip_address=ip_address, created_at__gte=now - window, created_at__lte=now
    )
    total = recent.count()
    if total < min_requests:
        return RuleResult("not_found_rate", 0.0, False, "not enough traffic to judge")

    not_found = recent.filter(status_code=404).count()
    rate = not_found / total
    return RuleResult(
        rule="not_found_rate",
        score=_scale(rate, rate_threshold),
        triggered=rate >= rate_threshold,
        detail=f"{not_found}/{total} requests were 404 ({rate:.0%})",
    )


def _longest_sequential_run(ids: list[int]) -> int:
    if not ids:
        return 0
    longest = current = 1
    for previous, current_id in zip(ids, ids[1:]):
        if current_id - previous in (1, -1):
            current += 1
            longest = max(longest, current)
        else:
            current = 1
    return longest


def sequential_id_scan_rule(
    ip_address: str | None,
    now: datetime,
    *,
    window: timedelta = timedelta(minutes=5),
    run_threshold: int = 3,
    sample_size: int = 200,
) -> RuleResult:
    """Score an IP walking a resource's IDs in order (e.g. /orders/1/, /2/, /3/)."""
    if not ip_address:
        return RuleResult("sequential_id_scan", 0.0, False, "no client ip")

    logs = RequestLog.objects.filter(
        ip_address=ip_address, created_at__gte=now - window, created_at__lte=now
    ).order_by("created_at")[:sample_size]

    ids_by_template: dict[str, list[int]] = {}
    for log in logs:
        match = _TRAILING_ID_PATTERN.search(log.path)
        if not match:
            continue
        ids_by_template.setdefault(normalize_path(log.path), []).append(int(match.group()))

    longest_run = max((_longest_sequential_run(ids) for ids in ids_by_template.values()), default=0)
    return RuleResult(
        rule="sequential_id_scan",
        score=_scale(longest_run, run_threshold),
        triggered=longest_run >= run_threshold,
        detail=f"longest sequential run: {longest_run}",
    )
