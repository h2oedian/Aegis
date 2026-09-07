from dataclasses import dataclass
from datetime import datetime

from .calibration import EvaluationSample


@dataclass(frozen=True)
class DetectionLatency:
    """When one attack window (from an aegis-sim-dataset campaign manifest)
    started, and when -- if ever -- the combined score for a request inside
    it first crossed the detection threshold."""

    scenario: str
    started_at: datetime
    detected_at: datetime | None

    @property
    def latency_seconds(self) -> float | None:
        if self.detected_at is None:
            return None
        return (self.detected_at - self.started_at).total_seconds()


def compute_detection_latencies(
    manifest_windows: list[dict],
    samples: list[EvaluationSample],
    *,
    rule_weight: float,
    detection_threshold: float,
) -> list[DetectionLatency]:
    """One DetectionLatency per attack window in the manifest.

    A window's "detected at" is the first sample inside it (by timestamp)
    whose combined score reaches ``detection_threshold`` -- normal windows
    are skipped, there's nothing to detect in them.
    """
    latencies = []
    for window in manifest_windows:
        if window.get("label") != "attack":
            continue
        started_at = datetime.fromisoformat(window["started_at"])
        ended_at = datetime.fromisoformat(window["ended_at"])
        window_samples = sorted(
            (sample for sample in samples if started_at <= sample.created_at < ended_at),
            key=lambda sample: sample.created_at,
        )
        detected_at = next(
            (
                sample.created_at
                for sample in window_samples
                if sample.combined_score(rule_weight=rule_weight) >= detection_threshold
            ),
            None,
        )
        latencies.append(
            DetectionLatency(
                scenario=window.get("scenario", ""), started_at=started_at, detected_at=detected_at
            )
        )
    return latencies


def mean_time_to_detection(latencies: list[DetectionLatency]) -> dict:
    detected = [latency for latency in latencies if latency.latency_seconds is not None]
    mean_seconds = (
        sum(latency.latency_seconds for latency in detected) / len(detected) if detected else None
    )
    return {
        "windows_evaluated": len(latencies),
        "windows_detected": len(detected),
        "windows_missed": len(latencies) - len(detected),
        "mean_seconds": mean_seconds,
    }
