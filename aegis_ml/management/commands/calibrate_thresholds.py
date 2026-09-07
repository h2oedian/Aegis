import json
from pathlib import Path

import joblib
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from django.core.management.base import BaseCommand, CommandError

from aegis_ml.calibration import (
    build_evaluation_samples,
    misclassified_samples,
    select_threshold_for_target_fpr,
)


def _plot_precision_recall_curve(curve, output_path: Path) -> None:
    recalls = [metrics.recall for metrics in curve]
    precisions = [metrics.precision for metrics in curve]
    figure, axis = plt.subplots()
    axis.plot(recalls, precisions, marker=".")
    axis.set_xlabel("Recall")
    axis.set_ylabel("Precision")
    axis.set_title("Precision / recall across combined-score thresholds")
    axis.set_xlim(0.0, 1.0)
    axis.set_ylim(0.0, 1.05)
    figure.savefig(output_path)
    plt.close(figure)


def _sample_to_dict(sample) -> dict:
    return {
        "ip_address": sample.ip_address,
        "path": sample.path,
        "created_at": sample.created_at.isoformat(),
        "scenario": sample.scenario,
        "rule_score": sample.rule_score,
        "model_score": sample.model_score,
    }


class Command(BaseCommand):
    help = (
        "Sweep combined-score thresholds against a labeled dataset, plot the "
        "precision/recall curve, and pick the threshold with the highest "
        "recall that still keeps the false-positive rate under --max-fpr."
    )

    def add_arguments(self, parser):
        parser.add_argument("--dataset", required=True, help="Labeled CSV from label_request_dataset")
        parser.add_argument("--model", required=True, help="Path to a trained AnomalyModel .joblib file")
        parser.add_argument("--rule-weight", type=float, default=0.5)
        parser.add_argument("--max-fpr", type=float, default=0.03)
        parser.add_argument("--curve-output", default="pr_curve.png")
        parser.add_argument("--report-output", default="calibration_report.json")
        parser.add_argument("--misclassified-limit", type=int, default=20)

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
            raise CommandError("Dataset has no rows to calibrate against")

        result = select_threshold_for_target_fpr(
            samples, rule_weight=options["rule_weight"], max_fpr=options["max_fpr"]
        )
        _plot_precision_recall_curve(result.curve, Path(options["curve_output"]))

        misclassified = misclassified_samples(
            samples,
            result.chosen.threshold,
            rule_weight=options["rule_weight"],
            limit=options["misclassified_limit"],
        )

        report = {
            "rule_weight": options["rule_weight"],
            "max_fpr": options["max_fpr"],
            "target_met": result.target_met,
            "chosen_threshold": result.chosen.threshold,
            "precision": result.chosen.precision,
            "recall": result.chosen.recall,
            "f1": result.chosen.f1,
            "false_positive_rate": result.chosen.false_positive_rate,
            "false_positives": [_sample_to_dict(sample) for sample in misclassified["false_positives"]],
            "false_negatives": [_sample_to_dict(sample) for sample in misclassified["false_negatives"]],
        }
        Path(options["report_output"]).write_text(json.dumps(report, indent=2), encoding="utf-8")

        if result.target_met:
            self.stdout.write(
                self.style.SUCCESS(
                    f"Threshold {result.chosen.threshold:.0f} meets the {options['max_fpr']:.0%} FPR "
                    f"target: precision={result.chosen.precision:.2f} recall={result.chosen.recall:.2f} "
                    f"fpr={result.chosen.false_positive_rate:.2%}"
                )
            )
        else:
            self.stdout.write(
                self.style.WARNING(
                    f"No threshold hit the {options['max_fpr']:.0%} FPR target; best achieved "
                    f"threshold={result.chosen.threshold:.0f} fpr={result.chosen.false_positive_rate:.2%} "
                    f"(recall={result.chosen.recall:.2f})"
                )
            )
        self.stdout.write(f"Precision/recall curve: {options['curve_output']}")
        self.stdout.write(f"Full report: {options['report_output']}")
