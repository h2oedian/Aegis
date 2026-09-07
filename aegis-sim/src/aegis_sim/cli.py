import argparse
import asyncio
import json

from .runner import run_simulation
from .safety import UnsafeTargetError, validate_target
from .scenarios import create_scenario


SCENARIOS = ("brute-force", "scrape", "id-enumeration", "injection-probes")


def positive_float(value: str) -> float:
    number = float(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("value must be greater than zero")
    return number


def bounded_rate(value: str) -> float:
    rate = positive_float(value)
    if rate > 1000:
        raise argparse.ArgumentTypeError("rate cannot exceed 1000 requests/second")
    return rate


def bounded_duration(value: str) -> float:
    duration = positive_float(value)
    if duration > 3600:
        raise argparse.ArgumentTypeError("duration cannot exceed 3600 seconds")
    return duration


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegis-sim",
        description="Run authorized traffic scenarios against an API you control.",
    )
    parser.add_argument("scenario", choices=SCENARIOS)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--rate", type=bounded_rate, default=5.0)
    parser.add_argument("--duration", type=bounded_duration, default=10.0)
    parser.add_argument("--timeout", type=positive_float, default=5.0)
    parser.add_argument("--username", default="aegis-test-user")
    parser.add_argument("--password-prefix", default="invalid-password-")
    parser.add_argument("--start-id", type=int, default=1)
    parser.add_argument("--token", help="Optional access token for the ID enumeration scenario")
    parser.add_argument(
        "--allow-public-target",
        action="store_true",
        help="Allow a public target only when you have explicit authorization.",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    try:
        base_url = validate_target(args.base_url, args.allow_public_target)
    except UnsafeTargetError as exc:
        raise SystemExit(f"Safety check failed: {exc}") from exc

    requests = create_scenario(
        args.scenario,
        username=args.username,
        password_prefix=args.password_prefix,
        start_id=args.start_id,
        token=args.token,
    )
    result = asyncio.run(
        run_simulation(
            scenario_name=args.scenario,
            requests=requests,
            base_url=base_url,
            rate=args.rate,
            duration=args.duration,
            timeout=args.timeout,
        )
    )
    print(json.dumps(result.summary(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

