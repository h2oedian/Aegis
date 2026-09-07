import math
import unittest
from datetime import datetime, timedelta, timezone as dt_timezone

from django.test import TestCase

from aegis_core.models import RequestLog
from aegis_core.paths import normalize_path

from .features import extract_features, extract_window_features


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


if __name__ == "__main__":
    unittest.main()
