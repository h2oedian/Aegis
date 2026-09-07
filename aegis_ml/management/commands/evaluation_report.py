import json
from pathlib import Path

import joblib
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from django.core.management.base import BaseCommand, CommandError

from aegis_ml.calibration import build_evaluation_samples, metrics_at_threshold
from aegis_ml.evaluation import compute_detection_latencies, mean_time_to_detection


def _plot_score_distribution(samples, output_path: Path, *, rule_weight: float) -> None:
    normal_scores = [s.combined_score(rule_weight=rule_weight) for s in samples if not s.is_attack]
    attack_scores = [s.combined_score(rule_weight=rule_weight) for s in samples if s.is_attack]

    figure, axis = plt.subplots()
    bins = list(range(0, 101, 5))
    if normal_scores:
        axis.hist(normal_scores, bins=bins, alpha=0.6, label=f"normal (n={len(normal_scores)})")
    if attack_scores:
        axis.hist(attack_scores, bins=bins, alpha=0.6, label=f"attack (n={len(attack_scores)})")
    axis.set_xlabel("Combined risk score")
    axis.set_ylabel("Requests")
    axis.set_title("Score distribution: normal vs attack")
    axis.legend()
    figure.savefig(output_path)
    plt.close(figure)


def _plot_latency_histogram(latencies, output_path: Path) -> None:
    values = [latency.latency_seconds for latency in latencies if latency.latency_seconds is not None]

    figure, axis = plt.subplots()
    if values:
        axis.hist(values, bins=min(20, max(1, len(values))))
    axis.set_xlabel("Seconds from attack start to detection")
    axis.set_ylabel("Attack windows")
    axis.set_title("Time to detection")
    figure.savefig(output_path)
    plt.close(figure)


class Command(BaseCommand):
    help = (
        "Produce the final precision/recall/F1/false-positive-rate and "
        "mean-time-to-detection numbers against a labeled dataset, with charts."
    )

    def add_arguments(self, parser):
        parser.add_argument("--dataset", required=True, help="Labeled CSV from label_request_dataset")
        parser.add_argument("--manifest", required=True, help="Campaign manifest from aegis-sim-dataset")
        parser.add_argument("--model", required=True, help="Trained AnomalyModel .joblib file")
        parser.add_argument("--threshold", type=float, required=True, help="Chosen decision threshold")
        parser.add_argument("--rule-weight", type=float, default=0.5)
        parser.add_argument(
            "--detection-threshold",
            type=float,
            default=None,
            help="Score at/above which a request counts as detected for MTTD (defaults to --threshold)",
        )
        parser.add_argument("--score-dist-output", default="score_distribution.png")
        parser.add_argument("--latency-output", default="detection_latency.png")
        parser.add_argument("--report-output", default="evaluation_report.json")

    def handle(self, *args, **options):
        try:
            model = joblib.load(options["model"])
        except OSError as exc:
            raise CommandError(f"Could not load model: {exc}") from exc

        try:
            samples = build_evaluation_samples(options["dataset"], model)
        except OSError as exc:
            raise CommandError(f"Could not read dataset: {exc}") from exc
        if not samples:
            raise CommandError("Dataset has no rows to evaluate")

        try:
            manifest_windows = json.loads(Path(options["manifest"]).read_text(encoding="utf-8"))
        except OSError as exc:
            raise CommandError(f"Could not read manifest: {exc}") from exc

        rule_weight = options["rule_weight"]
        threshold = options["threshold"]
        detection_threshold = (
            threshold if options["detection_threshold"] is None else options["detection_threshold"]
        )

        metrics = metrics_at_threshold(samples, threshold, rule_weight=rule_weight)
        latencies = compute_detection_latencies(
            manifest_windows, samples, rule_weight=rule_weight, detection_threshold=detection_threshold
        )
        mttd = mean_time_to_detection(latencies)

        _plot_score_distribution(samples, Path(options["score_dist_output"]), rule_weight=rule_weight)
        _plot_latency_histogram(latencies, Path(options["latency_output"]))

        report = {
            "threshold": threshold,
            "detection_threshold": detection_threshold,
            "rule_weight": rule_weight,
            "sample_count": len(samples),
            "precision": metrics.precision,
            "recall": metrics.recall,
            "f1": metrics.f1,
            "false_positive_rate": metrics.false_positive_rate,
            **mttd,
        }
        Path(options["report_output"]).write_text(json.dumps(report, indent=2), encoding="utf-8")

        self.stdout.write(
            self.style.SUCCESS(
                f"precision={metrics.precision:.2f} recall={metrics.recall:.2f} "
                f"f1={metrics.f1:.2f} fpr={metrics.false_positive_rate:.2%} "
                f"(n={len(samples)} @ threshold={threshold:.0f})"
            )
        )
        if mttd["mean_seconds"] is not None:
            self.stdout.write(
                f"mean time to detection: {mttd['mean_seconds']:.1f}s "
                f"({mttd['windows_detected']}/{mttd['windows_evaluated']} attack windows detected)"
            )
        else:
            self.stdout.write(self.style.WARNING("no attack windows were detected within their window"))
        self.stdout.write(f"charts: {options['score_dist_output']}, {options['latency_output']}")
        self.stdout.write(f"report: {options['report_output']}")
