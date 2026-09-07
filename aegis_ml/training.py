import csv
from dataclasses import dataclass
from datetime import datetime

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM

from .features import extract_features
from .model import AnomalyModel, ScoreCalibration, vectorize


@dataclass(frozen=True)
class TrainingSample:
    label: str
    features: dict[str, float]


def load_training_samples(csv_path: str) -> list[TrainingSample]:
    """Recompute a windowed feature vector for every row of a labeled dataset.

    ``csv_path`` is the CSV produced by the ``label_request_dataset``
    management command: one row per captured ``RequestLog``, each already
    tagged normal/attack. Each row's own timestamp is used as the "now" for
    its feature window, so every labeled request becomes one training
    sample summarizing its own recent history.
    """
    samples = []
    with open(csv_path, newline="", encoding="utf-8") as csv_file:
        for row in csv.DictReader(csv_file):
            occurred_at = datetime.fromisoformat(row["created_at"])
            features = extract_features(row["ip_address"], occurred_at)
            samples.append(TrainingSample(label=row["label"], features=features))
    return samples


def to_matrix(samples: list[TrainingSample]) -> np.ndarray:
    return np.array([vectorize(sample.features) for sample in samples], dtype=float)


def calibrate(estimator, x_normal: np.ndarray, *, low_percentile: float = 1.0, high_percentile: float = 99.0) -> ScoreCalibration:
    raw_scores = -estimator.decision_function(x_normal)
    return ScoreCalibration(
        low=float(np.percentile(raw_scores, low_percentile)),
        high=float(np.percentile(raw_scores, high_percentile)),
    )


def train_isolation_forest(x_normal: np.ndarray, *, random_state: int = 42, **kwargs) -> AnomalyModel:
    """Fit an Isolation Forest on normal traffic only, per the roadmap."""
    estimator = IsolationForest(random_state=random_state, **kwargs)
    estimator.fit(x_normal)
    return AnomalyModel(estimator=estimator, calibration=calibrate(estimator, x_normal))


def train_one_class_svm(x_normal: np.ndarray, *, nu: float = 0.05, gamma: str = "scale", **kwargs) -> AnomalyModel:
    """Fit a One-Class SVM on the same normal-only data, for comparison."""
    estimator = OneClassSVM(nu=nu, gamma=gamma, **kwargs)
    estimator.fit(x_normal)
    return AnomalyModel(estimator=estimator, calibration=calibrate(estimator, x_normal))


def compare_models(
    models: dict[str, AnomalyModel], samples: list[TrainingSample], *, flag_threshold: float = 60.0
) -> dict[str, dict]:
    """A quick, unweighted look at how each model treats the labeled samples.

    Full precision/recall calibration is a separate, later step; this is
    just enough to sanity-check that both models actually flag more attack
    traffic than normal traffic before either one is trusted.
    """
    report: dict[str, dict] = {}
    for name, model in models.items():
        scores_by_label = {"normal": [], "attack": []}
        for sample in samples:
            if sample.label in scores_by_label:
                scores_by_label[sample.label].append(model.score(sample.features))

        flagged = {
            label: sum(1 for score in scores if score >= flag_threshold)
            for label, scores in scores_by_label.items()
        }
        report[name] = {
            "mean_normal_score": _safe_mean(scores_by_label["normal"]),
            "mean_attack_score": _safe_mean(scores_by_label["attack"]),
            "normal_flagged": flagged["normal"],
            "normal_total": len(scores_by_label["normal"]),
            "attack_flagged": flagged["attack"],
            "attack_total": len(scores_by_label["attack"]),
        }
    return report


def _safe_mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0
