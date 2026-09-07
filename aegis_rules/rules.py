import re
from datetime import datetime, timedelta

from aegis_core.geoip import haversine_km, locate_ip
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


def impossible_travel_rule(
    user_id: int | None,
    current_ip: str | None,
    now: datetime,
    *,
    window: timedelta = timedelta(hours=6),
    max_plausible_speed_kmh: float = 900.0,  # roughly commercial-airliner cruise speed
    locate=locate_ip,
) -> RuleResult:
    """Score a user's requests implying faster-than-physically-possible travel.

    Grouped by ``user_id``, not IP -- by definition the two points being
    compared come from different IPs, so IP can't be the lookup key here
    the way it is for every other rule.
    """
    if not user_id or not current_ip:
        return RuleResult("impossible_travel", 0.0, False, "no authenticated user or ip")

    current_location = locate(current_ip)
    if current_location is None:
        return RuleResult("impossible_travel", 0.0, False, "current location unavailable")

    previous = (
        RequestLog.objects.filter(user_id=user_id, created_at__gte=now - window, created_at__lt=now)
        .exclude(ip_address=current_ip)
        .exclude(ip_address__isnull=True)
        .order_by("-created_at")
        .first()
    )
    if previous is None:
        return RuleResult("impossible_travel", 0.0, False, "no prior location to compare")

    previous_location = locate(previous.ip_address)
    if previous_location is None:
        return RuleResult("impossible_travel", 0.0, False, "previous location unavailable")

    elapsed_hours = max((now - previous.created_at).total_seconds() / 3600.0, 1e-6)
    distance_km = haversine_km(*previous_location, *current_location)
    implied_speed_kmh = distance_km / elapsed_hours

    return RuleResult(
        rule="impossible_travel",
        score=_scale(implied_speed_kmh, max_plausible_speed_kmh),
        triggered=implied_speed_kmh >= max_plausible_speed_kmh,
        detail=f"{distance_km:.0f}km in {elapsed_hours:.2f}h implies {implied_speed_kmh:.0f}km/h",
    )


def device_fingerprint_rule(
    token_fingerprint: str | None, request_fingerprint: str | None
) -> RuleResult:
    """Score a request whose device fingerprint doesn't match the one its
    access token was issued to (aegis_core.tokens/fingerprint)."""
    if not token_fingerprint or not request_fingerprint:
        return RuleResult("device_fingerprint_mismatch", 0.0, False, "no fingerprint to compare")
    if token_fingerprint == request_fingerprint:
        return RuleResult("device_fingerprint_mismatch", 0.0, False, "matches the token's device")
    return RuleResult(
        rule="device_fingerprint_mismatch",
        score=60.0,
        triggered=True,
        detail="request fingerprint does not match the token's bound device",
    )
