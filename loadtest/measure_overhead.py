"""Compare API latency with Aegis's middleware on vs off.

Runs the same Django app twice -- once with AEGIS_ENABLED=true, once with
AEGIS_ENABLED=false (config.settings compiles Aegis's middleware out of the
MIDDLEWARE list entirely in that case, see settings.py) -- and drives each
with a headless Locust run against /api/health/, the one endpoint in this
repo that passes through the full middleware stack. Aegis protects other
people's business endpoints (the Marketplace API demo), not itself, so this
is the honest thing to measure against here.

Usage:
    python loadtest/measure_overhead.py [--users 20] [--duration 20]
        [--max-overhead-percent 5] [--host 127.0.0.1] [--port 8811]

Requires the app's normal runtime dependencies plus loadtest/requirements.txt
(locust), and a reachable database/Redis per whatever DJANGO_SETTINGS_MODULE
is already configured in the environment -- this script does not choose or
override that; point it at a real environment (e.g. via `docker compose`)
for numbers that mean anything in production.
"""

import argparse
import csv
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class RunStats:
    request_count: int
    failure_count: int
    average_ms: float
    median_ms: float
    p95_ms: float


def _wait_for_server(base_url: str, *, timeout_seconds: float = 30.0) -> None:
    deadline = time.monotonic() + timeout_seconds
    last_error = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"{base_url}/api/health/", timeout=1.0) as response:
                if response.status == 200:
                    return
        except (urllib.error.URLError, ConnectionError, TimeoutError) as exc:
            last_error = exc
        time.sleep(0.3)
    raise RuntimeError(f"Server at {base_url} never became ready: {last_error}")


def _start_server(*, host: str, port: int, aegis_enabled: bool) -> subprocess.Popen:
    env = os.environ.copy()
    env["AEGIS_ENABLED"] = "true" if aegis_enabled else "false"
    process = subprocess.Popen(
        [sys.executable, "manage.py", "runserver", f"{host}:{port}", "--noreload"],
        cwd=REPO_ROOT,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        _wait_for_server(f"http://{host}:{port}")
    except Exception:
        process.terminate()
        raise
    return process


def _run_locust(*, base_url: str, users: int, duration: int, csv_prefix: Path) -> RunStats:
    subprocess.run(
        [
            sys.executable,
            "-m",
            "locust",
            "-f",
            str(REPO_ROOT / "loadtest" / "locustfile.py"),
            "--headless",
            "--host",
            base_url,
            "-u",
            str(users),
            "-r",
            str(max(1, users // 2)),
            "-t",
            f"{duration}s",
            "--csv",
            str(csv_prefix),
            "--only-summary",
        ],
        cwd=REPO_ROOT,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return _parse_stats_csv(Path(f"{csv_prefix}_stats.csv"))


def _parse_stats_csv(path: Path) -> RunStats:
    with open(path, newline="", encoding="utf-8") as csv_file:
        for row in csv.DictReader(csv_file):
            if row["Type"] == "Aggregated" or row["Name"] == "Aggregated":
                return RunStats(
                    request_count=int(row["Request Count"]),
                    failure_count=int(row["Failure Count"]),
                    average_ms=float(row["Average Response Time"]),
                    median_ms=float(row["Median Response Time"]),
                    p95_ms=float(row["95%"]),
                )
    raise RuntimeError(f"No aggregated row found in {path}")


def measure(*, host: str, port: int, users: int, duration: int, csv_dir: Path) -> dict[str, RunStats]:
    results = {}
    for label, aegis_enabled in (("aegis_off", False), ("aegis_on", True)):
        server = _start_server(host=host, port=port, aegis_enabled=aegis_enabled)
        try:
            results[label] = _run_locust(
                base_url=f"http://{host}:{port}",
                users=users,
                duration=duration,
                csv_prefix=csv_dir / label,
            )
        finally:
            server.terminate()
            server.wait(timeout=10)
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8811)
    parser.add_argument("--users", type=int, default=20)
    parser.add_argument("--duration", type=int, default=20, help="seconds per run")
    parser.add_argument("--max-overhead-percent", type=float, default=5.0)
    parser.add_argument("--output", default="overhead_report.json")
    args = parser.parse_args()

    csv_dir = Path(args.output).resolve().parent
    csv_dir.mkdir(parents=True, exist_ok=True)

    results = measure(
        host=args.host, port=args.port, users=args.users, duration=args.duration, csv_dir=csv_dir
    )
    off, on = results["aegis_off"], results["aegis_on"]

    overhead_percent = ((on.average_ms - off.average_ms) / off.average_ms * 100) if off.average_ms else 0.0
    within_budget = overhead_percent <= args.max_overhead_percent

    report = {
        "aegis_off": asdict(off),
        "aegis_on": asdict(on),
        "overhead_percent": round(overhead_percent, 2),
        "max_overhead_percent": args.max_overhead_percent,
        "within_budget": within_budget,
    }
    Path(args.output).write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(f"Aegis off: avg={off.average_ms:.2f}ms  median={off.median_ms:.2f}ms  p95={off.p95_ms:.2f}ms")
    print(f"Aegis on:  avg={on.average_ms:.2f}ms  median={on.median_ms:.2f}ms  p95={on.p95_ms:.2f}ms")
    verdict = "OK" if within_budget else "OVER BUDGET"
    print(f"Overhead: {overhead_percent:.1f}% (budget {args.max_overhead_percent:.1f}%) -- {verdict}")
    print(f"Report written to {args.output}")

    if not within_budget:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
