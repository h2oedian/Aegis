from dataclasses import dataclass, field
from datetime import datetime, timedelta

from django.db.models import Count
from django.db.models.functions import TruncMinute
from django.utils import timezone

from aegis_core.models import AuditLog, RequestLog
from aegis_ml.decision import DecisionEngine
from aegis_rules.engine import RuleEngine


@dataclass(frozen=True)
class VolumePoint:
    minute: datetime
    count: int
    height_percent: float


@dataclass(frozen=True)
class RiskyIP:
    ip_address: str
    score: float
    request_count: int
    triggered_rules: list[str]
    banned: bool


@dataclass(frozen=True)
class DashboardSnapshot:
    window_minutes: int
    volume: list[VolumePoint] = field(default_factory=list)
    risky_ips: list[RiskyIP] = field(default_factory=list)
    rule_breakdown: list[tuple[str, int]] = field(default_factory=list)
    recent_events: list[AuditLog] = field(default_factory=list)


def request_volume_by_minute(*, minutes: int, now: datetime) -> list[VolumePoint]:
    """One point per minute of the trailing window, zero-filled where there
    was no traffic, so a flat stretch of the chart reads as "quiet", not
    "missing data"."""
    end = now.replace(second=0, microsecond=0)
    start = end - timedelta(minutes=minutes)

    counts_by_minute = dict(
        RequestLog.objects.filter(created_at__gte=start, created_at__lte=now)
        .annotate(minute=TruncMinute("created_at"))
        .values("minute")
        .annotate(count=Count("id"))
        .values_list("minute", "count")
    )

    buckets = [start + timedelta(minutes=offset) for offset in range(minutes + 1)]
    raw_counts = [counts_by_minute.get(bucket, 0) for bucket in buckets]
    busiest = max(raw_counts) if raw_counts else 0

    return [
        VolumePoint(
            minute=bucket,
            count=count,
            height_percent=(count / busiest * 100.0) if busiest else 0.0,
        )
        for bucket, count in zip(buckets, raw_counts)
    ]


def _top_active_ips(*, minutes: int, limit: int, now: datetime) -> list[tuple[str, int]]:
    start = now - timedelta(minutes=minutes)
    rows = (
        RequestLog.objects.filter(created_at__gte=start, created_at__lte=now, ip_address__isnull=False)
        .values("ip_address")
        .annotate(request_count=Count("id"))
        .order_by("-request_count")[:limit]
    )
    return [(row["ip_address"], row["request_count"]) for row in rows]


def _score_active_ips(
    *, minutes: int, limit: int, now: datetime, engine: RuleEngine, decisions: DecisionEngine
) -> tuple[list[RiskyIP], list[tuple[str, int]]]:
    """Live rule score for each of the busiest IPs in the window (capped at
    ``limit`` for a page load's worth of query budget), plus how many of
    them tripped each rule -- a proxy for "attack type" that costs no extra
    queries since it's read off the same evaluation pass."""
    breakdown: dict[str, int] = {}
    risky: list[RiskyIP] = []

    for ip_address, request_count in _top_active_ips(minutes=minutes, limit=limit, now=now):
        evaluation = engine.evaluate(ip_address=ip_address, path="", now=now)
        for rule in evaluation.triggered_rules:
            breakdown[rule.rule] = breakdown.get(rule.rule, 0) + 1
        if evaluation.score > 0:
            risky.append(
                RiskyIP(
                    ip_address=ip_address,
                    score=evaluation.score,
                    request_count=request_count,
                    triggered_rules=[rule.rule for rule in evaluation.triggered_rules],
                    banned=decisions.is_banned(ip_address),
                )
            )

    risky.sort(key=lambda entry: entry.score, reverse=True)
    ranked_breakdown = sorted(breakdown.items(), key=lambda item: item[1], reverse=True)
    return risky, ranked_breakdown


def build_snapshot(
    *,
    window_minutes: int = 30,
    top_ips: int = 20,
    event_limit: int = 20,
    now: datetime | None = None,
    engine: RuleEngine | None = None,
    decisions: DecisionEngine | None = None,
) -> DashboardSnapshot:
    now = now or timezone.now()
    engine = engine or RuleEngine()
    decisions = decisions or DecisionEngine()

    risky_ips, rule_breakdown = _score_active_ips(
        minutes=window_minutes, limit=top_ips, now=now, engine=engine, decisions=decisions
    )
    return DashboardSnapshot(
        window_minutes=window_minutes,
        volume=request_volume_by_minute(minutes=window_minutes, now=now),
        risky_ips=risky_ips,
        rule_breakdown=rule_breakdown,
        recent_events=list(AuditLog.objects.order_by("-created_at")[:event_limit]),
    )
