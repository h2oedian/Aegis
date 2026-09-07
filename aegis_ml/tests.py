import csv
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone as dt_timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import joblib
import numpy as np
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.http import HttpResponse
from django.test import RequestFactory, TestCase, override_settings
from redis.exceptions import ConnectionError as RedisConnectionError

from aegis_core.audit import verify_chain
from aegis_core.fingerprint import compute_fingerprint
from aegis_core.models import AuditLog, RequestLog
from aegis_core.paths import normalize_path
from aegis_core.rate_limiter import RateLimitDecision
from aegis_core.tokens import issue_initial_pair

from .calibration import (
    EvaluationSample,
    build_evaluation_samples,
    metrics_at_threshold,
    misclassified_samples,
    select_threshold_for_target_fpr,
    sweep_thresholds,
)
from .decision import (
    TIER_ATTACK,
    TIER_NORMAL,
    TIER_RISKY,
    TIER_SUSPICIOUS,
    Decision,
    DecisionEngine,
    classify_score,
)
from .evaluation import DetectionLatency, compute_detection_latencies, mean_time_to_detection
from .features import extract_features, extract_window_features
from .middleware import AdaptiveResponseMiddleware
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


def _sample(
    label,
    rule_score,
    model_score,
    *,
    ip="203.0.113.60",
    path="/api/health/",
    scenario="",
    created_at=None,
):
    return EvaluationSample(
        label=label,
        rule_score=rule_score,
        model_score=model_score,
        ip_address=ip,
        path=path,
        created_at=created_at or datetime(2026, 1, 1, tzinfo=dt_timezone.utc),
        scenario=scenario,
    )


class RequestCountFakeModel:
    """Module-level (picklable) stand-in model for the calibration command test."""

    def score(self, features):
        return min(100.0, features["w1m_request_count"] * 10)


class MetricsAtThresholdTests(unittest.TestCase):
    def test_counts_confusion_matrix_and_derived_metrics(self):
        samples = [
            _sample("normal", 10, 0, path="/quiet"),
            _sample("normal", 60, 0, path="/noisy-but-fine"),
            _sample("attack", 80, 0, path="/caught"),
            _sample("attack", 20, 0, path="/missed"),
        ]

        metrics = metrics_at_threshold(samples, 50, rule_weight=1.0)

        self.assertEqual(metrics.true_positives, 1)
        self.assertEqual(metrics.false_positives, 1)
        self.assertEqual(metrics.true_negatives, 1)
        self.assertEqual(metrics.false_negatives, 1)
        self.assertAlmostEqual(metrics.precision, 0.5)
        self.assertAlmostEqual(metrics.recall, 0.5)
        self.assertAlmostEqual(metrics.false_positive_rate, 0.5)
        self.assertAlmostEqual(metrics.f1, 0.5)

    def test_zero_denominators_do_not_raise(self):
        metrics = metrics_at_threshold([], 50, rule_weight=1.0)
        self.assertEqual(metrics.precision, 0.0)
        self.assertEqual(metrics.recall, 0.0)
        self.assertEqual(metrics.false_positive_rate, 0.0)
        self.assertEqual(metrics.f1, 0.0)


class SweepThresholdsTests(unittest.TestCase):
    def test_covers_the_full_0_to_100_range(self):
        curve = sweep_thresholds([], rule_weight=1.0, step=1.0)
        self.assertEqual(len(curve), 101)
        self.assertEqual(curve[0].threshold, 0.0)
        self.assertEqual(curve[-1].threshold, 100.0)


class SelectThresholdForTargetFprTests(unittest.TestCase):
    def test_picks_the_lowest_threshold_meeting_the_target(self):
        normal_samples = [_sample("normal", score, 0) for score in range(100)]
        attack_samples = [_sample("attack", 100, 0) for _ in range(10)]

        result = select_threshold_for_target_fpr(
            normal_samples + attack_samples, rule_weight=1.0, max_fpr=0.03
        )

        self.assertTrue(result.target_met)
        self.assertEqual(result.chosen.threshold, 97.0)
        self.assertAlmostEqual(result.chosen.recall, 1.0)

    def test_reports_when_the_target_is_unreachable(self):
        normal_samples = [_sample("normal", 0, 0) for _ in range(8)] + [
            _sample("normal", 100, 0) for _ in range(2)
        ]

        result = select_threshold_for_target_fpr(normal_samples, rule_weight=1.0, max_fpr=0.03)

        self.assertFalse(result.target_met)
        self.assertGreater(result.chosen.false_positive_rate, 0.03)


class MisclassifiedSamplesTests(unittest.TestCase):
    def test_separates_false_positives_and_false_negatives(self):
        samples = [
            _sample("normal", 10, 0, path="/quiet"),
            _sample("normal", 90, 0, path="/loud-but-fine"),
            _sample("attack", 95, 0, path="/caught"),
            _sample("attack", 5, 0, path="/missed"),
        ]

        result = misclassified_samples(samples, 50, rule_weight=1.0)

        self.assertEqual([s.path for s in result["false_positives"]], ["/loud-but-fine"])
        self.assertEqual([s.path for s in result["false_negatives"]], ["/missed"])

    def test_respects_the_limit(self):
        samples = [_sample("normal", 90, 0, path=f"/fp-{i}") for i in range(5)]

        result = misclassified_samples(samples, 50, rule_weight=1.0, limit=2)

        self.assertEqual(len(result["false_positives"]), 2)


class BuildEvaluationSamplesTests(TestCase):
    def write_csv(self, path, rows):
        with open(path, "w", newline="", encoding="utf-8") as csv_file:
            writer = csv.DictWriter(
                csv_file,
                fieldnames=["created_at", "ip_address", "path", "query_string", "label", "scenario"],
            )
            writer.writeheader()
            writer.writerows(rows)

    def test_recomputes_rule_score_from_stored_history(self):
        ip = "203.0.113.70"
        now = datetime(2026, 5, 1, tzinfo=dt_timezone.utc)
        for offset in range(6):
            RequestLog.objects.create(
                ip_address=ip,
                path="/api/auth/login/",
                method="POST",
                status_code=401,
                duration_ms=1.0,
                created_at=now - timedelta(seconds=offset),
            )

        csv_path = Path(tempfile.mkdtemp()) / "dataset.csv"
        self.write_csv(
            csv_path,
            [
                {
                    "created_at": now.isoformat(),
                    "ip_address": ip,
                    "path": "/api/auth/login/",
                    "query_string": "",
                    "label": "attack",
                    "scenario": "brute-force",
                }
            ],
        )

        class FixedScoreModel:
            def score(self, features):
                return 42.0

        samples = build_evaluation_samples(str(csv_path), FixedScoreModel())

        self.assertEqual(len(samples), 1)
        sample = samples[0]
        self.assertEqual(sample.label, "attack")
        self.assertGreater(sample.rule_score, 0)  # unauthorized_attempts rule fires
        self.assertEqual(sample.model_score, 42.0)
        self.assertEqual(sample.scenario, "brute-force")

    def test_decodes_the_query_string_for_signature_detection(self):
        ip = "203.0.113.71"
        now = datetime(2026, 5, 1, tzinfo=dt_timezone.utc)
        csv_path = Path(tempfile.mkdtemp()) / "dataset.csv"
        self.write_csv(
            csv_path,
            [
                {
                    "created_at": now.isoformat(),
                    "ip_address": ip,
                    "path": "/api/products/",
                    "query_string": "search=%27+OR+%271%27%3D%271",
                    "label": "attack",
                    "scenario": "injection-probes",
                }
            ],
        )

        class ZeroScoreModel:
            def score(self, features):
                return 0.0

        samples = build_evaluation_samples(str(csv_path), ZeroScoreModel())

        self.assertEqual(len(samples), 1)
        self.assertGreater(samples[0].rule_score, 0)  # injection_signature rule fires


class CalibrateThresholdsCommandTests(TestCase):
    def test_produces_a_report_and_curve_meeting_the_target(self):
        base_time = datetime(2026, 6, 1, tzinfo=dt_timezone.utc)
        rows = []
        for index in range(30):
            ip = f"10.1.0.{index}"
            RequestLog.objects.create(
                ip_address=ip,
                path="/api/health/",
                method="GET",
                status_code=200,
                duration_ms=1.0,
                created_at=base_time,
            )
            rows.append(
                {
                    "created_at": base_time.isoformat(),
                    "ip_address": ip,
                    "path": "/api/health/",
                    "query_string": "",
                    "label": "normal",
                    "scenario": "normal-traffic",
                }
            )

        attack_ip = "10.1.1.1"
        for offset in range(20):
            RequestLog.objects.create(
                ip_address=attack_ip,
                path="/api/products/",
                method="GET",
                status_code=200,
                duration_ms=1.0,
                created_at=base_time - timedelta(seconds=offset),
            )
        rows.append(
            {
                "created_at": base_time.isoformat(),
                "ip_address": attack_ip,
                "path": "/api/products/",
                "query_string": "",
                "label": "attack",
                "scenario": "scrape",
            }
        )

        tmp_dir = Path(tempfile.mkdtemp())
        csv_path = tmp_dir / "dataset.csv"
        with open(csv_path, "w", newline="", encoding="utf-8") as csv_file:
            writer = csv.DictWriter(
                csv_file,
                fieldnames=["created_at", "ip_address", "path", "query_string", "label", "scenario"],
            )
            writer.writeheader()
            writer.writerows(rows)

        model_path = tmp_dir / "fake_model.joblib"
        joblib.dump(RequestCountFakeModel(), model_path)

        curve_path = tmp_dir / "pr_curve.png"
        report_path = tmp_dir / "calibration_report.json"

        call_command(
            "calibrate_thresholds",
            dataset=str(csv_path),
            model=str(model_path),
            curve_output=str(curve_path),
            report_output=str(report_path),
        )

        self.assertTrue(curve_path.exists())
        self.assertGreater(curve_path.stat().st_size, 0)

        report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertTrue(report["target_met"])
        self.assertEqual(report["chosen_threshold"], 6.0)
        self.assertEqual(report["recall"], 1.0)
        self.assertEqual(report["false_positive_rate"], 0.0)


class ClassifyScoreTests(unittest.TestCase):
    def test_matches_the_roadmap_response_table(self):
        self.assertEqual(classify_score(0), TIER_NORMAL)
        self.assertEqual(classify_score(29.9), TIER_NORMAL)
        self.assertEqual(classify_score(30), TIER_SUSPICIOUS)
        self.assertEqual(classify_score(59.9), TIER_SUSPICIOUS)
        self.assertEqual(classify_score(60), TIER_RISKY)
        self.assertEqual(classify_score(79.9), TIER_RISKY)
        self.assertEqual(classify_score(80), TIER_ATTACK)
        self.assertEqual(classify_score(100), TIER_ATTACK)


class DecisionJsonRoundTripTests(unittest.TestCase):
    def test_round_trips_through_json(self):
        decision = Decision(score=42.5, tier=TIER_SUSPICIOUS, rule_score=20.0, model_score=25.0)
        self.assertEqual(Decision.from_json(decision.to_json()), decision)


class DecisionEngineTests(unittest.TestCase):
    def setUp(self):
        self.redis_client = MagicMock()
        self.redis_client.get.return_value = None
        self.engine = DecisionEngine(redis_client=self.redis_client, rule_weight=1.0)

    def test_computes_and_caches_a_fresh_decision(self):
        decision = self.engine.decide(
            ip_address="203.0.113.80", path="/api/health/", query_params={}
        )

        self.assertEqual(decision.tier, TIER_NORMAL)
        self.assertEqual(decision.score, 0.0)
        self.redis_client.set.assert_called_once()
        cache_key = self.redis_client.set.call_args.args[0]
        self.assertEqual(cache_key, "aegis:decision:203.0.113.80")

    def test_returns_the_cached_decision_without_recomputing(self):
        cached = Decision(score=90.0, tier=TIER_ATTACK, rule_score=90.0, model_score=0.0)
        self.redis_client.get.return_value = cached.to_json()

        with patch("aegis_ml.decision.RuleEngine.evaluate") as evaluate:
            decision = self.engine.decide(
                ip_address="203.0.113.81", path="/api/health/", query_params={}
            )

        evaluate.assert_not_called()
        self.assertEqual(decision, cached)

    def test_skips_the_cache_entirely_without_an_ip(self):
        self.engine.decide(ip_address=None, path="/api/health/", query_params={})
        self.redis_client.get.assert_not_called()
        self.redis_client.set.assert_not_called()

    def test_falls_back_to_a_fresh_decision_when_the_cache_is_unavailable(self):
        self.redis_client.get.side_effect = RedisConnectionError("offline")
        self.redis_client.set.side_effect = RedisConnectionError("offline")

        decision = self.engine.decide(
            ip_address="203.0.113.82", path="/api/health/", query_params={}
        )

        self.assertEqual(decision.tier, TIER_NORMAL)

    def test_ban_sets_a_key_with_the_configured_ttl(self):
        with override_settings(AEGIS_BAN_DURATION_SECONDS=120):
            self.engine.ban("203.0.113.83")

        self.redis_client.set.assert_called_once_with("aegis:ban:203.0.113.83", "1", ex=120)

    def test_is_banned_reflects_key_existence(self):
        self.redis_client.exists.return_value = 1
        self.assertTrue(self.engine.is_banned("203.0.113.84"))

        self.redis_client.exists.return_value = 0
        self.assertFalse(self.engine.is_banned("203.0.113.84"))

    def test_is_banned_fails_safe_when_redis_is_unavailable(self):
        self.redis_client.exists.side_effect = RedisConnectionError("offline")
        self.assertFalse(self.engine.is_banned("203.0.113.85"))


@override_settings(AEGIS_SHADOW_MODE=True)
class AdaptiveResponseMiddlewareShadowModeTests(TestCase):
    def test_attack_tier_decision_does_not_block_the_request(self):
        attack_decision = Decision(score=95.0, tier=TIER_ATTACK, rule_score=95.0, model_score=0.0)
        with patch("aegis_ml.middleware.DecisionEngine.decide", return_value=attack_decision):
            response = self.client.get("/api/health/")

        self.assertEqual(response.status_code, 200)

class AdaptiveResponseMiddlewareUnitTests(TestCase):
    def test_attaches_the_decision_to_the_request(self):
        decision = Decision(score=10.0, tier=TIER_NORMAL, rule_score=10.0, model_score=0.0)
        captured = {}

        def probe(request):
            captured["decision"] = request.aegis_decision
            return HttpResponse("ok")

        request = RequestFactory().get("/api/health/")
        with patch("aegis_ml.middleware.DecisionEngine.decide", return_value=decision):
            AdaptiveResponseMiddleware(probe)(request)

        self.assertEqual(captured["decision"], decision)

    def test_passes_the_peeked_identity_and_fingerprint_to_the_decision_engine(self):
        user = get_user_model().objects.create_user(username="middleware-user")
        pair = issue_initial_pair(user, fingerprint="device-abc")
        decision = Decision(score=0.0, tier=TIER_NORMAL, rule_score=0.0, model_score=0.0)

        request = RequestFactory().get(
            "/api/health/",
            HTTP_AUTHORIZATION=f"Bearer {pair.access}",
            HTTP_USER_AGENT="curl/8.0",
            HTTP_ACCEPT_LANGUAGE="en-US",
            HTTP_ACCEPT_ENCODING="gzip",
        )
        expected_request_fingerprint = compute_fingerprint(request)

        with patch(
            "aegis_ml.middleware.DecisionEngine.decide", return_value=decision
        ) as decide:
            AdaptiveResponseMiddleware(lambda req: HttpResponse("ok"))(request)

        kwargs = decide.call_args.kwargs
        self.assertEqual(kwargs["user_id"], user.pk)
        self.assertEqual(kwargs["token_fingerprint"], "device-abc")
        self.assertEqual(kwargs["request_fingerprint"], expected_request_fingerprint)

    def test_an_unauthenticated_request_has_no_identity_or_token_fingerprint(self):
        decision = Decision(score=0.0, tier=TIER_NORMAL, rule_score=0.0, model_score=0.0)
        request = RequestFactory().get("/api/health/")

        with patch(
            "aegis_ml.middleware.DecisionEngine.decide", return_value=decision
        ) as decide:
            AdaptiveResponseMiddleware(lambda req: HttpResponse("ok"))(request)

        kwargs = decide.call_args.kwargs
        self.assertIsNone(kwargs["user_id"])
        self.assertIsNone(kwargs["token_fingerprint"])
        self.assertIsNotNone(kwargs["request_fingerprint"])


@override_settings(AEGIS_SHADOW_MODE=False)
class AdaptiveResponseMiddlewareEnforcingTests(TestCase):
    def test_attack_tier_blocks_and_records_a_ban(self):
        attack_decision = Decision(score=95.0, tier=TIER_ATTACK, rule_score=95.0, model_score=0.0)
        with patch("aegis_ml.middleware.DecisionEngine.decide", return_value=attack_decision), patch(
            "aegis_ml.middleware.DecisionEngine.is_banned", return_value=False
        ), patch("aegis_ml.middleware.DecisionEngine.ban") as ban:
            response = self.client.get("/api/health/")

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["error"], "temporarily_blocked")
        ban.assert_called_once()

    def test_attack_tier_block_records_an_audit_event(self):
        attack_decision = Decision(score=95.0, tier=TIER_ATTACK, rule_score=95.0, model_score=0.0)
        with patch("aegis_ml.middleware.DecisionEngine.decide", return_value=attack_decision), patch(
            "aegis_ml.middleware.DecisionEngine.is_banned", return_value=False
        ), patch("aegis_ml.middleware.DecisionEngine.ban"):
            self.client.get("/api/health/")

        event = AuditLog.objects.get(event_type="attack_blocked")
        self.assertEqual(event.payload["ip_address"], "127.0.0.1")
        self.assertEqual(event.payload["score"], 95.0)
        self.assertTrue(verify_chain().valid)

    def test_already_banned_ip_is_rejected_without_recomputing_a_decision(self):
        with patch("aegis_ml.middleware.DecisionEngine.is_banned", return_value=True), patch(
            "aegis_ml.middleware.DecisionEngine.decide"
        ) as decide:
            response = self.client.get("/api/health/")

        self.assertEqual(response.status_code, 403)
        decide.assert_not_called()

    def test_risky_tier_returns_a_challenge_response(self):
        risky_decision = Decision(score=70.0, tier=TIER_RISKY, rule_score=70.0, model_score=0.0)
        with patch("aegis_ml.middleware.DecisionEngine.decide", return_value=risky_decision), patch(
            "aegis_ml.middleware.DecisionEngine.is_banned", return_value=False
        ):
            response = self.client.get("/api/health/")

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["error"], "challenge_required")

    def test_normal_tier_is_still_subject_to_rate_limiting(self):
        normal_decision = Decision(score=5.0, tier=TIER_NORMAL, rule_score=5.0, model_score=0.0)
        denied = RateLimitDecision(allowed=False, remaining_tokens=0.0, capacity=10.0)
        with patch("aegis_ml.middleware.DecisionEngine.decide", return_value=normal_decision), patch(
            "aegis_ml.middleware.DecisionEngine.is_banned", return_value=False
        ), patch(
            "aegis_ml.middleware.TokenBucketRateLimiter.check_for_risk_score", return_value=denied
        ):
            response = self.client.get("/api/health/")

        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.json()["error"], "rate_limited")

    def test_normal_tier_within_rate_limit_passes_through(self):
        normal_decision = Decision(score=5.0, tier=TIER_NORMAL, rule_score=5.0, model_score=0.0)
        allowed = RateLimitDecision(allowed=True, remaining_tokens=9.0, capacity=10.0)
        with patch("aegis_ml.middleware.DecisionEngine.decide", return_value=normal_decision), patch(
            "aegis_ml.middleware.DecisionEngine.is_banned", return_value=False
        ), patch(
            "aegis_ml.middleware.TokenBucketRateLimiter.check_for_risk_score", return_value=allowed
        ):
            response = self.client.get("/api/health/")

        self.assertEqual(response.status_code, 200)


class ComputeDetectionLatenciesTests(unittest.TestCase):
    def setUp(self):
        self.window_start = datetime(2026, 1, 1, tzinfo=dt_timezone.utc)
        self.window = {
            "label": "attack",
            "scenario": "brute-force",
            "started_at": self.window_start.isoformat(),
            "ended_at": (self.window_start + timedelta(minutes=5)).isoformat(),
        }

    def test_latency_is_measured_from_the_window_start_to_the_first_crossing_sample(self):
        samples = [
            _sample("attack", 10, 0, created_at=self.window_start + timedelta(seconds=10)),
            _sample("attack", 90, 0, created_at=self.window_start + timedelta(seconds=45)),
            _sample("attack", 95, 0, created_at=self.window_start + timedelta(seconds=90)),
        ]

        latencies = compute_detection_latencies(
            [self.window], samples, rule_weight=1.0, detection_threshold=60.0
        )

        self.assertEqual(len(latencies), 1)
        self.assertEqual(latencies[0].latency_seconds, 45.0)

    def test_a_window_with_no_crossing_sample_is_never_detected(self):
        samples = [
            _sample("attack", 10, 0, created_at=self.window_start + timedelta(seconds=10)),
            _sample("attack", 20, 0, created_at=self.window_start + timedelta(seconds=20)),
        ]

        latencies = compute_detection_latencies(
            [self.window], samples, rule_weight=1.0, detection_threshold=60.0
        )

        self.assertIsNone(latencies[0].detected_at)
        self.assertIsNone(latencies[0].latency_seconds)

    def test_normal_windows_are_skipped(self):
        normal_window = {**self.window, "label": "normal"}
        samples = [_sample("normal", 90, 0, created_at=self.window_start + timedelta(seconds=5))]

        latencies = compute_detection_latencies(
            [normal_window], samples, rule_weight=1.0, detection_threshold=60.0
        )

        self.assertEqual(latencies, [])

    def test_samples_outside_the_window_are_ignored(self):
        samples = [_sample("attack", 90, 0, created_at=self.window_start - timedelta(seconds=5))]

        latencies = compute_detection_latencies(
            [self.window], samples, rule_weight=1.0, detection_threshold=60.0
        )

        self.assertIsNone(latencies[0].detected_at)


class MeanTimeToDetectionTests(unittest.TestCase):
    def test_averages_only_the_detected_windows(self):
        latencies = [
            DetectionLatency("brute-force", datetime(2026, 1, 1, tzinfo=dt_timezone.utc), datetime(2026, 1, 1, 0, 0, 10, tzinfo=dt_timezone.utc)),
            DetectionLatency("scrape", datetime(2026, 1, 1, tzinfo=dt_timezone.utc), datetime(2026, 1, 1, 0, 0, 30, tzinfo=dt_timezone.utc)),
            DetectionLatency("injection-probes", datetime(2026, 1, 1, tzinfo=dt_timezone.utc), None),
        ]

        result = mean_time_to_detection(latencies)

        self.assertEqual(result["windows_evaluated"], 3)
        self.assertEqual(result["windows_detected"], 2)
        self.assertEqual(result["windows_missed"], 1)
        self.assertAlmostEqual(result["mean_seconds"], 20.0)

    def test_no_windows_at_all_is_well_defined(self):
        result = mean_time_to_detection([])
        self.assertEqual(result["windows_evaluated"], 0)
        self.assertIsNone(result["mean_seconds"])

    def test_all_windows_missed_gives_no_mean(self):
        latencies = [DetectionLatency("scrape", datetime(2026, 1, 1, tzinfo=dt_timezone.utc), None)]
        result = mean_time_to_detection(latencies)
        self.assertEqual(result["windows_missed"], 1)
        self.assertIsNone(result["mean_seconds"])


class EvaluationReportCommandTests(TestCase):
    def test_produces_a_report_with_charts_and_mttd(self):
        base_time = datetime(2026, 7, 1, tzinfo=dt_timezone.utc)
        attack_ip = "10.2.0.1"

        rows = []
        for index in range(15):
            offset = base_time + timedelta(seconds=index * 5)
            RequestLog.objects.create(
                ip_address=attack_ip,
                path="/api/auth/login/",
                method="POST",
                status_code=200,
                duration_ms=1.0,
                created_at=offset,
            )
            rows.append(
                {
                    "created_at": offset.isoformat(),
                    "ip_address": attack_ip,
                    "path": "/api/auth/login/",
                    "query_string": "",
                    "label": "attack",
                    "scenario": "brute-force",
                }
            )

        normal_ip = "10.2.1.1"
        normal_time = base_time
        RequestLog.objects.create(
            ip_address=normal_ip,
            path="/api/health/",
            method="GET",
            status_code=200,
            duration_ms=1.0,
            created_at=normal_time,
        )
        rows.append(
            {
                "created_at": normal_time.isoformat(),
                "ip_address": normal_ip,
                "path": "/api/health/",
                "query_string": "",
                "label": "normal",
                "scenario": "normal-traffic",
            }
        )

        manifest = [
            {
                "label": "attack",
                "scenario": "brute-force",
                "started_at": base_time.isoformat(),
                "ended_at": (base_time + timedelta(minutes=5)).isoformat(),
            }
        ]

        tmp_dir = Path(tempfile.mkdtemp())
        dataset_path = tmp_dir / "dataset.csv"
        with open(dataset_path, "w", newline="", encoding="utf-8") as csv_file:
            writer = csv.DictWriter(
                csv_file,
                fieldnames=["created_at", "ip_address", "path", "query_string", "label", "scenario"],
            )
            writer.writeheader()
            writer.writerows(rows)

        manifest_path = tmp_dir / "manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

        model_path = tmp_dir / "fake_model.joblib"
        joblib.dump(RequestCountFakeModel(), model_path)

        score_dist_path = tmp_dir / "score_distribution.png"
        latency_path = tmp_dir / "detection_latency.png"
        report_path = tmp_dir / "evaluation_report.json"

        call_command(
            "evaluation_report",
            dataset=str(dataset_path),
            manifest=str(manifest_path),
            model=str(model_path),
            threshold=50.0,
            score_dist_output=str(score_dist_path),
            latency_output=str(latency_path),
            report_output=str(report_path),
        )

        self.assertTrue(score_dist_path.exists())
        self.assertGreater(score_dist_path.stat().st_size, 0)
        self.assertTrue(latency_path.exists())
        self.assertGreater(latency_path.stat().st_size, 0)

        report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(report["sample_count"], 16)
        self.assertEqual(report["windows_evaluated"], 1)
        self.assertIn("precision", report)
        self.assertIn("recall", report)
        self.assertIn("f1", report)
        self.assertIn("false_positive_rate", report)


if __name__ == "__main__":
    unittest.main()
