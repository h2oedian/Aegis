from pathlib import Path

import joblib
from django.core.management.base import BaseCommand, CommandError

from aegis_ml.training import (
    compare_models,
    load_training_samples,
    to_matrix,
    train_isolation_forest,
    train_one_class_svm,
)


class Command(BaseCommand):
    help = (
        "Train the Isolation Forest (and a One-Class SVM for comparison) on "
        "the normal-traffic rows of a labeled dataset CSV, then save both."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--dataset",
            required=True,
            help="Labeled CSV produced by the label_request_dataset command",
        )
        parser.add_argument(
            "--output-dir",
            default="models",
            help="Directory to write isolation_forest.joblib / one_class_svm.joblib into",
        )
        parser.add_argument(
            "--flag-threshold",
            type=float,
            default=60.0,
            help="Score (0-100) above which a sample is considered flagged, for the comparison report",
        )

    def handle(self, *args, **options):
        try:
            samples = load_training_samples(options["dataset"])
        except OSError as exc:
            raise CommandError(f"Could not read dataset: {exc}") from exc

        normal_samples = [sample for sample in samples if sample.label == "normal"]
        if not normal_samples:
            raise CommandError("Dataset has no rows labeled 'normal' to train on")

        x_normal = to_matrix(normal_samples)

        models = {
            "isolation_forest": train_isolation_forest(x_normal),
            "one_class_svm": train_one_class_svm(x_normal),
        }

        output_dir = Path(options["output_dir"])
        output_dir.mkdir(parents=True, exist_ok=True)
        for name, model in models.items():
            joblib.dump(model, output_dir / f"{name}.joblib")

        report = compare_models(models, samples, flag_threshold=options["flag_threshold"])
        for name, stats in report.items():
            self.stdout.write(
                self.style.SUCCESS(
                    f"{name}: mean score normal={stats['mean_normal_score']:.1f} "
                    f"attack={stats['mean_attack_score']:.1f}; flagged "
                    f"{stats['attack_flagged']}/{stats['attack_total']} attack rows, "
                    f"{stats['normal_flagged']}/{stats['normal_total']} normal rows "
                    f"(threshold={options['flag_threshold']})"
                )
            )

        self.stdout.write(
            self.style.SUCCESS(
                f"Trained on {len(normal_samples)} normal samples, saved to {output_dir}/"
            )
        )
