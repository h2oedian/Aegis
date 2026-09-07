import math
import statistics
from collections import Counter
from dataclasses import dataclass, fields
from datetime import datetime, timedelta

from django.utils import timezone

from aegis_core.models import RequestLog
from aegis_core.paths import normalize_path

WINDOW_MINUTES = (1, 5, 60)


def _entropy(values: list[float], *, bin_width: float = 0.25, max_bins: int = 40) -> float:
    """Shannon entropy (bits) of ``values`` after bucketing into fixed-width bins.

    A bot hitting an endpoint at a near-constant rate produces intervals
    that pile into one or two bins (low entropy); irregular, human-like
    pacing spreads across many bins (higher entropy).
    """
    if len(values) < 2:
        return 0.0
    counts = Counter(min(max_bins - 1, int(value // bin_width)) for value in values)
    total = sum(counts.values())
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


@dataclass(frozen=True)
class WindowFeatures:
    request_count: int
    request_rate_per_second: float
    unique_endpoints: int
    error_ratio: float
    mean_interval_seconds: float
    stdev_interval_seconds: float
    interval_entropy: float
    method_get_ratio: float
    method_post_ratio: float
    method_other_ratio: float
    unique_user_agents: int

    def as_dict(self, *, prefix: str) -> dict[str, float]:
        return {f"{prefix}_{field.name}": getattr(self, field.name) for field in fields(self)}


def _empty_window_features() -> WindowFeatures:
    return WindowFeatures(
        request_count=0,
        request_rate_per_second=0.0,
        unique_endpoints=0,
        error_ratio=0.0,
        mean_interval_seconds=0.0,
        stdev_interval_seconds=0.0,
        interval_entropy=0.0,
        method_get_ratio=0.0,
        method_post_ratio=0.0,
        method_other_ratio=0.0,
        unique_user_agents=0,
    )


def extract_window_features(
    ip_address: str, now: datetime, *, window_minutes: int
) -> WindowFeatures:
    window = timedelta(minutes=window_minutes)
    logs = list(
        RequestLog.objects.filter(
            ip_address=ip_address, created_at__gte=now - window, created_at__lte=now
        ).order_by("created_at")
    )

    request_count = len(logs)
    if request_count == 0:
        return _empty_window_features()

    unique_endpoints = len({normalize_path(log.path) for log in logs})
    error_count = sum(1 for log in logs if log.status_code >= 400)

    timestamps = [log.created_at.timestamp() for log in logs]
    intervals = [later - earlier for earlier, later in zip(timestamps, timestamps[1:])]

    method_counts = Counter(log.method.upper() for log in logs)
    method_get_ratio = method_counts.get("GET", 0) / request_count
    method_post_ratio = method_counts.get("POST", 0) / request_count

    return WindowFeatures(
        request_count=request_count,
        request_rate_per_second=request_count / window.total_seconds(),
        unique_endpoints=unique_endpoints,
        error_ratio=error_count / request_count,
        mean_interval_seconds=statistics.fmean(intervals) if intervals else 0.0,
        stdev_interval_seconds=statistics.pstdev(intervals) if len(intervals) > 1 else 0.0,
        interval_entropy=_entropy(intervals),
        method_get_ratio=method_get_ratio,
        method_post_ratio=method_post_ratio,
        method_other_ratio=max(0.0, 1.0 - method_get_ratio - method_post_ratio),
        unique_user_agents=len({log.user_agent for log in logs if log.user_agent}),
    )


def _hour_of_day_features(now: datetime) -> dict[str, float]:
    """Cyclical (sin/cos) encoding so hour 23 and hour 0 are seen as adjacent."""
    radians = 2 * math.pi * (now.hour / 24)
    return {"hour_sin": math.sin(radians), "hour_cos": math.cos(radians)}


def extract_features(ip_address: str, now: datetime | None = None) -> dict[str, float]:
    """Build one IP's full feature vector at a point in time.

    Combines request-rate/error/timing/method/user-agent statistics across
    the 1, 5, and 60 minute trailing windows (each prefixed e.g. ``w5m_``)
    with a cyclical hour-of-day encoding, so the model sees both short
    bursts and slower behavioural drift.
    """
    now = now or timezone.now()
    features: dict[str, float] = {}
    for minutes in WINDOW_MINUTES:
        window_features = extract_window_features(ip_address, now, window_minutes=minutes)
        features.update(window_features.as_dict(prefix=f"w{minutes}m"))
    features.update(_hour_of_day_features(now))
    return features
