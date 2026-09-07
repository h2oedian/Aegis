import asyncio
import random
import time
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field

import httpx

from .scenarios import RequestSpec


@dataclass
class SimulationResult:
    scenario: str
    attempted: int = 0
    errors: int = 0
    status_codes: Counter = field(default_factory=Counter)
    latencies_ms: list[float] = field(default_factory=list)

    def summary(self) -> dict:
        ordered = sorted(self.latencies_ms)
        mean = sum(ordered) / len(ordered) if ordered else 0.0
        p95_index = max(0, int(len(ordered) * 0.95) - 1)
        return {
            "scenario": self.scenario,
            "attempted": self.attempted,
            "errors": self.errors,
            "status_codes": dict(sorted(self.status_codes.items())),
            "mean_latency_ms": round(mean, 3),
            "p95_latency_ms": round(ordered[p95_index], 3) if ordered else 0.0,
        }


async def run_simulation(
    *,
    scenario_name: str,
    requests: Iterator[RequestSpec],
    base_url: str,
    rate: float,
    duration: float,
    timeout: float,
    jitter: float = 0.0,
) -> SimulationResult:
    """Replay ``requests`` against ``base_url`` at roughly ``rate`` req/s.

    ``jitter`` (0 <= jitter < 1) randomizes each pause by that fraction
    instead of holding a fixed cadence, to mimic irregular human traffic.
    """
    result = SimulationResult(scenario=scenario_name)
    interval = 1.0 / rate
    deadline = time.monotonic() + duration
    next_request_at = time.monotonic()

    async with httpx.AsyncClient(base_url=base_url, timeout=timeout) as client:
        while time.monotonic() < deadline:
            request = next(requests)
            started_at = time.perf_counter()
            result.attempted += 1
            try:
                response = await client.request(
                    request.method,
                    request.path,
                    params=request.params,
                    json=request.json,
                    headers=request.headers,
                )
                result.status_codes[response.status_code] += 1
                result.latencies_ms.append((time.perf_counter() - started_at) * 1000)
            except httpx.HTTPError:
                result.errors += 1

            step = interval * random.uniform(1 - jitter, 1 + jitter) if jitter else interval
            next_request_at += step
            delay = next_request_at - time.monotonic()
            if delay > 0:
                await asyncio.sleep(delay)

    return result

