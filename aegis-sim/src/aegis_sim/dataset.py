import math
import random
from dataclasses import dataclass
from datetime import datetime, timezone

from .runner import run_simulation
from .scenarios import ATTACK_SCENARIOS, create_scenario


@dataclass(frozen=True)
class CampaignWindow:
    label: str  # "normal" or "attack"
    scenario: str
    duration_s: float


@dataclass(frozen=True)
class CampaignRecord:
    label: str
    scenario: str
    started_at: str
    ended_at: str
    attempted: int
    errors: int


def build_campaign_plan(
    *,
    total_seconds: float,
    normal_share: float,
    attack_burst_s: float,
    seed: int | None = None,
) -> list[CampaignWindow]:
    """Interleave normal traffic with attack bursts across ``total_seconds``.

    ``normal_share`` (0-1) is the fraction of total time spent on normal
    traffic; the remainder is split into ``attack_burst_s``-long bursts,
    one per attack scenario, shuffled and cycled to fill the time. Attack
    bursts are separated by normal-traffic windows so each attack is a
    labeled spike inside a baseline of ordinary behaviour.
    """
    if not 0 < normal_share < 1:
        raise ValueError("normal_share must be between 0 and 1 (exclusive)")
    if total_seconds <= 0 or attack_burst_s <= 0:
        raise ValueError("total_seconds and attack_burst_s must be positive")

    rng = random.Random(seed)
    attack_total_s = total_seconds * (1 - normal_share)
    normal_total_s = total_seconds - attack_total_s

    burst_count = max(1, math.ceil(attack_total_s / attack_burst_s))
    scenario_cycle = list(ATTACK_SCENARIOS)
    rng.shuffle(scenario_cycle)
    attack_scenarios = [
        scenario_cycle[index % len(scenario_cycle)] for index in range(burst_count)
    ]

    remaining_attack_s = attack_total_s
    attack_windows = []
    for index, scenario in enumerate(attack_scenarios):
        is_last = index == burst_count - 1
        duration = remaining_attack_s if is_last else min(attack_burst_s, remaining_attack_s)
        remaining_attack_s -= duration
        attack_windows.append(CampaignWindow("attack", scenario, duration))

    normal_slice_count = burst_count + 1
    normal_slice_s = normal_total_s / normal_slice_count

    plan: list[CampaignWindow] = []
    for attack_window in attack_windows:
        plan.append(CampaignWindow("normal", "normal-traffic", normal_slice_s))
        plan.append(attack_window)
    plan.append(CampaignWindow("normal", "normal-traffic", normal_slice_s))
    return plan


async def run_campaign(
    *,
    plan: list[CampaignWindow],
    base_url: str,
    normal_rate: float,
    attack_rate: float,
    normal_jitter: float,
    timeout: float,
    username: str,
    password_prefix: str,
    start_id: int,
    token: str | None,
) -> list[CampaignRecord]:
    manifest: list[CampaignRecord] = []
    for window in plan:
        if window.duration_s <= 0:
            continue
        requests = create_scenario(
            window.scenario,
            username=username,
            password_prefix=password_prefix,
            start_id=start_id,
            token=token,
        )
        is_normal = window.label == "normal"
        started_at = datetime.now(timezone.utc)
        result = await run_simulation(
            scenario_name=window.scenario,
            requests=requests,
            base_url=base_url,
            rate=normal_rate if is_normal else attack_rate,
            duration=window.duration_s,
            timeout=timeout,
            jitter=normal_jitter if is_normal else 0.0,
        )
        ended_at = datetime.now(timezone.utc)
        manifest.append(
            CampaignRecord(
                label=window.label,
                scenario=window.scenario,
                started_at=started_at.isoformat(),
                ended_at=ended_at.isoformat(),
                attempted=result.attempted,
                errors=result.errors,
            )
        )
    return manifest
