import argparse
import asyncio
import json
from dataclasses import asdict

from .dataset import build_campaign_plan, run_campaign
from .safety import UnsafeTargetError, validate_target


def bounded_hours(value: str) -> float:
    hours = float(value)
    if not 0 < hours <= 24:
        raise argparse.ArgumentTypeError("hours must be in the range (0, 24]")
    return hours


def bounded_share(value: str) -> float:
    share = float(value)
    if not 0 < share < 1:
        raise argparse.ArgumentTypeError("value must be in the range (0, 1)")
    return share


def positive_float(value: str) -> float:
    number = float(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("value must be greater than zero")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegis-sim-dataset",
        description=(
            "Generate a labeled normal/attack traffic campaign against an API "
            "you control, for training and evaluating the detection engine."
        ),
    )
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--hours", type=bounded_hours, default=1.0)
    parser.add_argument(
        "--normal-share",
        type=bounded_share,
        default=0.85,
        help="Fraction of total time spent on normal traffic (default: 0.85).",
    )
    parser.add_argument(
        "--attack-burst-seconds",
        type=positive_float,
        default=60.0,
        help="Length of each attack burst, in seconds (default: 60).",
    )
    parser.add_argument("--normal-rate", type=positive_float, default=0.3)
    parser.add_argument("--attack-rate", type=positive_float, default=8.0)
    parser.add_argument("--normal-jitter", type=float, default=0.6)
    parser.add_argument("--timeout", type=positive_float, default=5.0)
    parser.add_argument("--username", default="aegis-test-user")
    parser.add_argument("--password-prefix", default="invalid-password-")
    parser.add_argument("--start-id", type=int, default=1)
    parser.add_argument("--token", help="Optional access token for normal traffic / id enumeration")
    parser.add_argument("--seed", type=int, help="Seed for reproducible campaign plans")
    parser.add_argument("--output", default="dataset_manifest.json")
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

    plan = build_campaign_plan(
        total_seconds=args.hours * 3600,
        normal_share=args.normal_share,
        attack_burst_s=args.attack_burst_seconds,
        seed=args.seed,
    )

    manifest = asyncio.run(
        run_campaign(
            plan=plan,
            base_url=base_url,
            normal_rate=args.normal_rate,
            attack_rate=args.attack_rate,
            normal_jitter=args.normal_jitter,
            timeout=args.timeout,
            username=args.username,
            password_prefix=args.password_prefix,
            start_id=args.start_id,
            token=args.token,
        )
    )

    with open(args.output, "w", encoding="utf-8") as manifest_file:
        json.dump([asdict(record) for record in manifest], manifest_file, indent=2)

    print(f"Wrote {len(manifest)} labeled windows to {args.output}")


if __name__ == "__main__":
    main()
