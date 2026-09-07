import csv
import tempfile
import unittest
from datetime import datetime, timedelta, timezone as dt_timezone
from pathlib import Path

import joblib
import numpy as np
from django.core.management import call_command
from django.test import TestCase

from aegis_core.models import RequestLog
from aegis_core.paths import normalize_path

from .features import extract_features, extract_window_features
from .model import FEATURE_NAMES, AnomalyModel, ScoreCalibration
from .risk import combined_risk_score
from .training import (
    TrainingSample,
    compare_models,
    load_training_samples,
    to_matrix,
    train_isolation_forest,
    train_one_class_svm,
)


class NormalizePathTests(unittest.TestCase):
    def test_collapses_numeric_segments(self):
        self.assertEqual(normalize_path("/api/orders/7/"), "/api/orders/{id}/")

    def test_treats_different_ids_as_the_same_template(self):
        self.assertEqual(normalize_path("/api/orders/7/"), normalize_path("/api/orders/8/"))

    def test_leaves_paths_without_digits_untouched(self):
        self.assertEqual(normalize_path("/api/health/"), "/api/health/")


class WindowFeatureExtractionTests(TestCase):
    def setUp(self):
        self.now = datetime(2026, 1, 1, tzinfo=dt_timezone.utc)
        self.ip = "203.0.113.30"

    def make_log(self, offset_seconds, *, path="/api/health/", method="GET", status_code=200, user_agent="ua"):
        RequestLog.objects.create(
            ip_address=self.ip,
            path=path,
            method=method,
            status_code=status_code,
            duration_ms=1.0,
            user_agent=user_agent,
            created_at=self.now - timedelta(seconds=offset_seconds),
        )

    def test_empty_window_is_all_zeros(self):
        features = extract_window_features(self.ip, self.now, window_minutes=5)
        self.assertEqual(features.request_count, 0)
        self.assertEqual(features.request_rate_per_second, 0.0)
        self.assertEqual(features.unique_endpoints, 0)

    def test_request_rate_and_count(self):
        for offset in range(10):
            self.make_log(offset)
        features = extract_window_features(self.ip, self.now, window_minutes=1)
        self.assertEqual(features.request_count, 10)
        self.assertAlmostEqual(features.request_rate_per_second, 10 / 60)

    def test_unique_endpoints_ignores_numeric_ids(self):
        for order_id in range(5):
            self.make_log(order_id, path=f"/api/orders/{order_id}/")
        self.make_log(10, path="/api/health/")
        features = extract_window_features(self.ip, self.now, window_minutes=5)
        self.assertEqual(features.unique_endpoints, 2)

    def test_error_ratio(self):
        for offset, status in enumerate((200, 200, 404, 500)):
            self.make_log(offset, status_code=status)
        features = extract_window_features(self.ip, self.now, window_minutes=5)
        self.assertAlmostEqual(features.error_ratio, 0.5)

    def test_interval_statistics_for_evenly_spaced_requests(self):
        for offset in (0, 10, 20, 30):
            self.make_log(offset)
        features = extract_window_features(self.ip, self.now, window_minutes=5)
        self.assertAlmostEqual(features.mean_interval_seconds, 10.0)
        self.assertAlmostEqual(features.stdev_interval_seconds, 0.0)

    def test_regular_bursts_score_lower_entropy_than_irregular_pacing(self):
        for offset in (0, 5, 10, 15, 20, 25, 30):
            self.make_log(offset)
        regular = extract_window_features(self.ip, self.now, window_minutes=5)

        RequestLog.objects.filter(ip_address=self.ip).delete()
        for offset in (0, 1, 9, 10, 24, 25, 31):
            self.make_log(offset)
        irregular = extract_window_features(self.ip, self.now, window_minutes=5)

        self.assertLess(regular.interval_entropy, irregular.interval_entropy)

    def test_method_ratios_sum_to_one(self):
        for method in ("GET", "GET", "POST", "DELETE"):
            self.make_log(1, method=method)
        features = extract_window_features(self.ip, self.now, window_minutes=5)
        self.assertAlmostEqual(
            features.method_get_ratio + features.method_post_ratio + features.method_other_ratio,
            1.0,
        )
        self.assertAlmostEqual(features.method_get_ratio, 0.5)

    def test_unique_user_agents(self):
        for agent in ("curl/8.0", "curl/8.0", "python-requests/2.0"):
            self.make_log(1, user_agent=agent)
        features = extract_window_features(self.ip, self.now, window_minutes=5)
        self.assertEqual(features.unique_user_agents, 2)

    def test_window_only_counts_requests_inside_it(self):
        self.make_log(30)  # inside a 1-minute window
        self.make_log(3600)  # an hour ago, outside it
        features = extract_window_features(self.ip, self.now, window_minutes=1)
        self.assertEqual(features.request_count, 1)


class FullFeatureVectorTests(TestCase):
    def setUp(self):
        self.now = datetime(2026, 6, 15, 6, tzinfo=dt_timezone.utc)
        self.ip = "203.0.113.40"

    def test_combines_all_windows_and_hour_of_day(self):
        RequestLog.objects.create(
            ip_address=self.ip,
            path="/api/health/",
            method="GET",
            status_code=200,
            duration_ms=1.0,
            created_at=self.now,
        )
        features = extract_features(self.ip, self.now)

        for minutes in (1, 5, 60):
            self.assertIn(f"w{minutes}m_request_count", features)
        self.assertEqual(features["w1m_request_count"], 1)
        self.assertIn("hour_sin", features)
        self.assertIn("hour_cos", features)

    def test_hour_of_day_is_encoded_cyclically(self):
        midnight = extract_features(self.ip, datetime(2026, 1, 1, 0, tzinfo=dt_timezone.utc))
        self.assertAlmostEqual(midnight["hour_sin"], 0.0, places=9)
        self.assertAlmostEqual(midnight["hour_cos"], 1.0, places=9)

        six_am = extract_features(self.ip, datetime(2026, 1, 1, 6, tzinfo=dt_timezone.utc))
        self.assertAlmostEqual(six_am["hour_sin"], 1.0, places=9)
        self.assertAlmostEqual(six_am["hour_cos"], 0.0, places=9)


class ScoreCalibrationTests(unittest.TestCase):
    def test_maps_low_end_to_zero_and_high_end_to_hundred(self):
        calibration = ScoreCalibration(low=0.0, high=10.0)
        self.assertEqual(calibration.to_100(0.0), 0.0)
        self.assertEqual(calibration.to_100(10.0), 100.0)
        self.assertEqual(calibration.to_100(5.0), 50.0)

    def test_clamps_outside_the_calibrated_range(self):
        calibration = ScoreCalibration(low=0.0, high=10.0)
        self.assertEqual(calibration.to_100(-5.0), 0.0)
        self.assertEqual(calibration.to_100(50.0), 100.0)

    def test_degenerate_range_returns_zero(self):
        calibration = ScoreCalibration(low=5.0, high=5.0)
        self.assertEqual(calibration.to_100(5.0), 0.0)


class AnomalyModelScoringTests(unittest.TestCase):
    class _StubEstimator:
        """decision_function returns -(last feature), so score() is driven
        entirely by one known feature -- lets vectorization be checked
        without needing a real fit."""

        def decision_function(self, vectors):
            return np.array([-vector[-1] for vector in vectors])

    def test_vectorizes_by_feature_name_and_flips_decision_function(self):
        model = AnomalyModel(
            estimator=self._StubEstimator(),
            calibration=ScoreCalibration(low=0.0, high=10.0),
        )
        features = dict.fromkeys(FEATURE_NAMES, 0.0)
        features["hour_cos"] = 7.0  # the last name in FEATURE_NAMES

        self.assertEqual(model.raw_anomaly_score(features), 7.0)
        self.assertEqual(model.score(features), 70.0)


class TrainAnomalyModelTests(unittest.TestCase):
    def _vector_to_features(self, vector):
        return dict(zip(FEATURE_NAMES, vector))

    def test_isolation_forest_trained_only_on_normal_scores_outliers_higher(self):
        rng = np.random.default_rng(42)
        n_features = len(FEATURE_NAMES)
        x_normal = rng.normal(loc=0.0, scale=1.0, size=(200, n_features))
        model = train_isolation_forest(x_normal, n_estimators=50)

        inlier = self._vector_to_features(np.zeros(n_features))
        outlier = self._vector_to_features(np.full(n_features, 50.0))

        self.assertGreater(model.score(outlier), model.score(inlier))

    def test_one_class_svm_trained_only_on_normal_scores_outliers_higher(self):
        rng = np.random.default_rng(7)
        n_features = len(FEATURE_NAMES)
        x_normal = rng.normal(loc=0.0, scale=1.0, size=(200, n_features))
        model = train_one_class_svm(x_normal)

        inlier = self._vector_to_features(np.zeros(n_features))
        outlier = self._vector_to_features(np.full(n_features, 50.0))

        self.assertGreater(model.score(outlier), model.score(inlier))


class CompareModelsTests(unittest.TestCase):
    class _FakeModel:
        def __init__(self, score_by_marker):
            self._scores = score_by_marker

        def score(self, features):
            return self._scores[features["marker"]]

    def test_reports_mean_scores_and_flag_counts_per_label(self):
        samples = [
            TrainingSample(label="normal", features={"marker": "n1"}),
            TrainingSample(label="normal", features={"marker": "n2"}),
            TrainingSample(label="attack", features={"marker": "a1"}),
            TrainingSample(label="attack", features={"marker": "a2"}),
        ]
        model = self._FakeModel({"n1": 10.0, "n2": 20.0, "a1": 70.0, "a2": 90.0})

        report = compare_models({"fake": model}, samples, flag_threshold=60.0)

        stats = report["fake"]
        self.assertAlmostEqual(stats["mean_normal_score"], 15.0)
        self.assertAlmostEqual(stats["mean_attack_score"], 80.0)
        self.assertEqual(stats["attack_flagged"], 2)
        self.assertEqual(stats["normal_flagged"], 0)


class CombinedRiskScoreTests(unittest.TestCase):
    def test_equal_weight_averages_the_two_scores(self):
        self.assertAlmostEqual(combined_risk_score(80.0, 20.0, rule_weight=0.5), 50.0)

    def test_weight_one_uses_only_the_rule_score(self):
        self.assertAlmostEqual(combined_risk_score(80.0, 20.0, rule_weight=1.0), 80.0)

    def test_weight_zero_uses_only_the_model_score(self):
        self.assertAlmostEqual(combined_risk_score(80.0, 20.0, rule_weight=0.0), 20.0)

    def test_result_stays_within_bounds(self):
        self.assertLessEqual(combined_risk_score(100.0, 100.0), 100.0)
        self.assertGreaterEqual(combined_risk_score(0.0, 0.0), 0.0)


class LoadTrainingSamplesTests(TestCase):
    def setUp(self):
        self.ip = "203.0.113.50"
        self.timestamp = datetime(2026, 3, 1, 12, tzinfo=dt_timezone.utc)
        RequestLog.objects.create(
            ip_address=self.ip,
            path="/api/health/",
            method="GET",
            status_code=200,
            duration_ms=1.0,
            created_at=self.timestamp,
        )

    def write_csv(self, rows):
        path = Path(tempfile.mkdtemp()) / "dataset.csv"
        with open(path, "w", newline="", encoding="utf-8") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=["created_at", "ip_address", "label"])
            writer.writeheader()
            writer.writerows(rows)
        return path

    def test_recomputes_features_from_the_row_timestamp_and_keeps_the_label(self):
        csv_path = self.write_csv(
            [{"created_at": self.timestamp.isoformat(), "ip_address": self.ip, "label": "normal"}]
        )

        samples = load_training_samples(str(csv_path))

        self.assertEqual(len(samples), 1)
        self.assertEqual(samples[0].label, "normal")
        self.assertEqual(samples[0].features["w1m_request_count"], 1)

    def test_matrix_shape_matches_feature_count(self):
        csv_path = self.write_csv(
            [{"created_at": self.timestamp.isoformat(), "ip_address": self.ip, "label": "normal"}]
        )

        matrix = to_matrix(load_training_samples(str(csv_path)))

        self.assertEqual(matrix.shape, (1, len(FEATURE_NAMES)))


class TrainAnomalyModelsCommandTests(TestCase):
    def test_trains_and_saves_both_models(self):
        base_time = datetime(2026, 4, 1, tzinfo=dt_timezone.utc)
        rows = []
        for index in range(20):
            ip = f"10.0.0.{index}"
            RequestLog.objects.create(
                ip_address=ip,
                path="/api/health/",
                method="GET",
                status_code=200,
                duration_ms=1.0,
                created_at=base_time,
            )
            rows.append({"created_at": base_time.isoformat(), "ip_address": ip, "label": "normal"})

        attack_ip = "10.0.1.1"
        for offset, order_id in enumerate(range(1, 7)):
            RequestLog.objects.create(
                ip_address=attack_ip,
                path=f"/api/orders/{order_id}/",
                method="GET",
                status_code=200,
                duration_ms=1.0,
                created_at=base_time - timedelta(seconds=offset),
            )
        rows.append({"created_at": base_time.isoformat(), "ip_address": attack_ip, "label": "attack"})

        tmp_dir = Path(tempfile.mkdtemp())
        csv_path = tmp_dir / "dataset.csv"
        with open(csv_path, "w", newline="", encoding="utf-8") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=["created_at", "ip_address", "label"])
            writer.writeheader()
            writer.writerows(rows)

        output_dir = tmp_dir / "models"
        call_command("train_anomaly_models", dataset=str(csv_path), output_dir=str(output_dir))

        self.assertTrue((output_dir / "isolation_forest.joblib").exists())
        self.assertTrue((output_dir / "one_class_svm.joblib").exists())

        loaded_model = joblib.load(output_dir / "isolation_forest.joblib")
        self.assertIn("w1m_request_count", loaded_model.feature_names)


if __name__ == "__main__":
    unittest.main()
