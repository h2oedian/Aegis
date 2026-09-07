from dataclasses import dataclass, fields

from .features import WINDOW_MINUTES, WindowFeatures

_WINDOW_FIELD_NAMES = tuple(field.name for field in fields(WindowFeatures))

# Fixed feature order, derived from the dataclass/window definitions rather
# than dict iteration order, so a saved model always sees vectors built the
# same way it was trained on.
FEATURE_NAMES = tuple(
    f"w{minutes}m_{name}" for minutes in WINDOW_MINUTES for name in _WINDOW_FIELD_NAMES
) + ("hour_sin", "hour_cos")


def vectorize(features: dict[str, float]) -> list[float]:
    return [features[name] for name in FEATURE_NAMES]


@dataclass(frozen=True)
class ScoreCalibration:
    """Maps a raw anomaly score to 0-100 using the training set's own spread.

    ``low``/``high`` are percentiles of the raw score over normal training
    traffic: a request scoring at or below ``low`` is unremarkable (0), one
    at or above ``high`` is as anomalous as the most extreme normal sample
    seen during training or worse (100).
    """

    low: float
    high: float

    def to_100(self, raw_score: float) -> float:
        if self.high <= self.low:
            return 0.0
        scaled = (raw_score - self.low) / (self.high - self.low)
        return max(0.0, min(100.0, scaled * 100.0))


@dataclass
class AnomalyModel:
    """A fitted scikit-learn outlier detector plus its score calibration."""

    estimator: object
    calibration: ScoreCalibration
    feature_names: tuple[str, ...] = FEATURE_NAMES

    def raw_anomaly_score(self, features: dict[str, float]) -> float:
        vector = [[features[name] for name in self.feature_names]]
        # decision_function: higher means "more normal". Flip it so a higher
        # value here means "more anomalous", matching the risk-score sense.
        return float(-self.estimator.decision_function(vector)[0])

    def score(self, features: dict[str, float]) -> float:
        return self.calibration.to_100(self.raw_anomaly_score(features))
