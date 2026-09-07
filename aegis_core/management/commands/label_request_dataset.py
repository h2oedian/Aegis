import csv
import json
from datetime import datetime

from django.core.management.base import BaseCommand, CommandError

from aegis_core.models import RequestLog

FIELDNAMES = (
    "created_at",
    "path",
    "query_string",
    "method",
    "status_code",
    "duration_ms",
    "ip_address",
    "user_agent",
    "user_id",
    "token_jti",
    "label",
    "scenario",
)


def load_manifest(manifest_path):
    with open(manifest_path, "r", encoding="utf-8") as manifest_file:
        return json.load(manifest_file)


def labeled_rows(windows):
    """Yield one dict per RequestLog row captured inside each manifest window."""
    for window in windows:
        started_at = datetime.fromisoformat(window["started_at"])
        ended_at = datetime.fromisoformat(window["ended_at"])
        logs = RequestLog.objects.filter(
            created_at__gte=started_at, created_at__lt=ended_at
        ).order_by("created_at")
        for log in logs:
            yield {
                "created_at": log.created_at.isoformat(),
                "path": log.path,
                "query_string": log.query_string,
                "method": log.method,
                "status_code": log.status_code,
                "duration_ms": log.duration_ms,
                "ip_address": log.ip_address or "",
                "user_agent": log.user_agent,
                "user_id": log.user_id or "",
                "token_jti": log.token_jti,
                "label": window["label"],
                "scenario": window["scenario"],
            }


class Command(BaseCommand):
    help = (
        "Label RequestLog rows captured during an aegis-sim dataset campaign "
        "(normal/attack) and export them to a CSV for the detection engine."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--manifest",
            required=True,
            help="Path to the campaign manifest JSON produced by aegis-sim-dataset",
        )
        parser.add_argument(
            "--output",
            default="dataset.csv",
            help="Path to write the labeled CSV dataset to (default: dataset.csv)",
        )

    def handle(self, *args, **options):
        try:
            windows = load_manifest(options["manifest"])
        except (OSError, json.JSONDecodeError) as exc:
            raise CommandError(f"Could not read manifest: {exc}") from exc

        counts = {"normal": 0, "attack": 0}
        with open(options["output"], "w", newline="", encoding="utf-8") as output_file:
            writer = csv.DictWriter(output_file, fieldnames=FIELDNAMES)
            writer.writeheader()
            for row in labeled_rows(windows):
                writer.writerow(row)
                counts[row["label"]] = counts.get(row["label"], 0) + 1

        total = sum(counts.values())
        self.stdout.write(
            self.style.SUCCESS(
                f"Wrote {total} labeled rows to {options['output']} "
                f"(normal={counts.get('normal', 0)}, attack={counts.get('attack', 0)})"
            )
        )
