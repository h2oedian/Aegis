import csv
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import parse_qs

from aegis_rules.engine import RuleEngine

from .features import extract_features
from .model import AnomalyModel
from .risk import combined_risk_score


def _parse_query_string(query_string: str) -> dict[str, str]:
    parsed = parse_qs(query_string, keep_blank_values=True)
    return {key: values[-1] for key, values in parsed.items()}


@dataclass(frozen=True)
class EvaluationSample:
    """One labeled request, scored by both the rule engine and the model.

    Keeps enough context (ip/path/scenario/time) that a flagged sample can
    actually be inspected by a person, not just counted.
    """

    label: str
    rule_score: float
    model_score: float
    ip_address: str
    path: str
    created_at: datetime
    scenario: str

    @property
    def is_attack(self) -> bool:
        return self.label == "attack"

    def combined_score(self, *, rule_weight: float) -> float:
        return combined_risk_score(self.rule_score, self.model_score, rule_weight=rule_weight)


def build_evaluation_samples(
    csv_path: str, model: AnomalyModel, *, engine: RuleEngine | None = None
) -> list[EvaluationSample]:
    """Replay a label_request_dataset CSV through the rule engine and model.

    Each row's rule score is computed the same way it would be live -- the
    stateful rules query that IP's RequestLog history (already in the
    database the CSV was exported from), and the signature rule gets the
    row's own query string.
    """
    engine = engine or RuleEngine()
    samples = []
    with open(csv_path, newline="", encoding="utf-8") as csv_file:
        for row in csv.DictReader(csv_file):
            occurred_at = datetime.fromisoformat(row["created_at"])
            rule_result = engine.evaluate(
                ip_address=row["ip_address"],
                path=row["path"],
                query_params=_parse_query_string(row.get("query_string", "")),
                now=occurred_at,
            )
            features = extract_features(row["ip_address"], occurred_at)
            samples.append(
                EvaluationSample(
                    label=row["label"],
                    rule_score=rule_result.score,
                    model_score=model.score(features),
                    ip_address=row["ip_address"],
                    path=row["path"],
                    created_at=occurred_at,
                    scenario=row.get("scenario", ""),
                )
            )
    return samples


@dataclass(frozen=True)
class ThresholdMetrics:
    threshold: float
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int

    @property
    def precision(self) -> float:
        denominator = self.true_positives + self.false_positives
        return self.true_positives / denominator if denominator else 0.0

    @property
    def recall(self) -> float:
        denominator = self.true_positives + self.false_negatives
        return self.true_positives / denominator if denominator else 0.0

    @property
    def false_positive_rate(self) -> float:
        denominator = self.false_positives + self.true_negatives
        return self.false_positives / denominator if denominator else 0.0

    @property
    def f1(self) -> float:
        precision, recall = self.precision, self.recall
        return 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0


def metrics_at_threshold(
    samples: list[EvaluationSample], threshold: float, *, rule_weight: float
) -> ThresholdMetrics:
    true_positives = false_positives = true_negatives = false_negatives = 0
    for sample in samples:
        predicted_attack = sample.combined_score(rule_weight=rule_weight) >= threshold
        if sample.is_attack and predicted_attack:
            true_positives += 1
        elif sample.is_attack and not predicted_attack:
            false_negatives += 1
        elif not sample.is_attack and predicted_attack:
            false_positives += 1
        else:
            true_negatives += 1
    return ThresholdMetrics(
        threshold=threshold,
        true_positives=true_positives,
        false_positives=false_positives,
        true_negatives=true_negatives,
        false_negatives=false_negatives,
    )


def sweep_thresholds(
    samples: list[EvaluationSample], *, rule_weight: float, step: float = 1.0
) -> list[ThresholdMetrics]:
    """One ThresholdMetrics per threshold from 0 to 100, for the PR curve."""
    thresholds = [step * i for i in range(int(100 / step) + 1)]
    return [metrics_at_threshold(samples, threshold, rule_weight=rule_weight) for threshold in thresholds]


@dataclass(frozen=True)
class CalibrationResult:
    chosen: ThresholdMetrics
    target_met: bool
    curve: list[ThresholdMetrics]


def select_threshold_for_target_fpr(
    samples: list[EvaluationSample], *, rule_weight: float, max_fpr: float = 0.03, step: float = 1.0
) -> CalibrationResult:
    """Pick the lowest threshold whose false-positive rate is <= ``max_fpr``.

    Raising the threshold only ever drives the FPR down and recall down
    with it, so the lowest threshold that still satisfies the FPR target
    is the one that keeps the most recall. If nothing hits the target, the
    threshold with the smallest achieved FPR is returned instead, flagged
    as not meeting it.
    """
    curve = sweep_thresholds(samples, rule_weight=rule_weight, step=step)
    for metrics in curve:
        if metrics.false_positive_rate <= max_fpr:
            return CalibrationResult(chosen=metrics, target_met=True, curve=curve)

    best = min(curve, key=lambda metrics: metrics.false_positive_rate)
    return CalibrationResult(chosen=best, target_met=False, curve=curve)


def misclassified_samples(
    samples: list[EvaluationSample], threshold: float, *, rule_weight: float, limit: int = 20
) -> dict[str, list[EvaluationSample]]:
    """False positives and false negatives at ``threshold``, for manual review."""
    false_positives = []
    false_negatives = []
    for sample in samples:
        predicted_attack = sample.combined_score(rule_weight=rule_weight) >= threshold
        if not sample.is_attack and predicted_attack:
            false_positives.append(sample)
        elif sample.is_attack and not predicted_attack:
            false_negatives.append(sample)
    return {
        "false_positives": false_positives[:limit],
        "false_negatives": false_negatives[:limit],
    }
