import unittest
from datetime import datetime, timedelta, timezone as dt_timezone

from django.contrib.auth import get_user_model
from django.test import TestCase

from aegis_core.models import RequestLog

from .engine import RuleEngine
from .rules import (
    device_fingerprint_rule,
    impossible_travel_rule,
    not_found_rate_rule,
    sequential_id_scan_rule,
    unauthorized_attempts_rule,
)
from .signatures import scan_injection_signatures

LONDON = (51.5074, -0.1278)
NEW_YORK = (40.7128, -74.0060)


def _fake_locate(coordinates_by_ip):
    return lambda ip: coordinates_by_ip.get(ip)


class InjectionSignatureTests(unittest.TestCase):
    def test_detects_sql_injection_in_query_param(self):
        result = scan_injection_signatures("/api/products/", {"search": "' OR '1'='1"})
        self.assertTrue(result.triggered)
        self.assertEqual(result.detail, "sqli")
        self.assertGreater(result.score, 0)

    def test_detects_xss_in_query_param(self):
        result = scan_injection_signatures(
            "/api/products/", {"search": "<script>alert('aegis')</script>"}
        )
        self.assertTrue(result.triggered)
        self.assertIn("xss", result.detail)

    def test_detects_path_traversal_in_path(self):
        result = scan_injection_signatures("/api/files/../../etc/passwd", {})
        self.assertTrue(result.triggered)
        self.assertIn("path_traversal", result.detail)

    def test_multiple_signatures_score_higher_than_one(self):
        single = scan_injection_signatures("/api/products/", {"search": "' OR '1'='1"})
        combined = scan_injection_signatures(
            "/api/products/", {"search": "' OR '1'='1", "cb": "<script>alert(1)</script>"}
        )
        self.assertGreater(combined.score, single.score)

    def test_benign_search_term_does_not_trigger(self):
        result = scan_injection_signatures("/api/products/", {"search": "running shoes"})
        self.assertFalse(result.triggered)
        self.assertEqual(result.score, 0.0)

    def test_score_is_never_capped_below_matches(self):
        result = scan_injection_signatures(
            "/api/x/../../etc/passwd",
            {"a": "' OR '1'='1", "b": "<script>x</script>"},
        )
        self.assertEqual(result.score, 100.0)


class StatefulRuleTests(TestCase):
    def setUp(self):
        self.now = datetime(2026, 1, 1, tzinfo=dt_timezone.utc)
        self.ip = "203.0.113.10"

    def make_log(self, offset_seconds, status_code, path="/api/health/"):
        RequestLog.objects.create(
            ip_address=self.ip,
            path=path,
            method="GET",
            status_code=status_code,
            duration_ms=1.0,
            created_at=self.now - timedelta(seconds=offset_seconds),
        )

    def test_unauthorized_attempts_rule_triggers_past_threshold(self):
        for offset in range(6):
            self.make_log(offset, 401)
        result = unauthorized_attempts_rule(self.ip, self.now, threshold=5)
        self.assertTrue(result.triggered)
        self.assertGreaterEqual(result.score, 50.0)

    def test_unauthorized_attempts_rule_ignores_old_requests(self):
        for offset in range(6):
            self.make_log(offset + 3600, 401)  # outside the default 5-minute window
        result = unauthorized_attempts_rule(self.ip, self.now, threshold=5)
        self.assertFalse(result.triggered)
        self.assertEqual(result.score, 0.0)

    def test_unauthorized_attempts_rule_without_ip_is_inert(self):
        result = unauthorized_attempts_rule(None, self.now)
        self.assertFalse(result.triggered)
        self.assertEqual(result.score, 0.0)

    def test_not_found_rate_rule_needs_minimum_traffic(self):
        self.make_log(1, 404)
        self.make_log(2, 404)
        result = not_found_rate_rule(self.ip, self.now, min_requests=5)
        self.assertFalse(result.triggered)

    def test_not_found_rate_rule_triggers_on_high_ratio(self):
        for offset in range(8):
            self.make_log(offset, 404 if offset < 6 else 200)
        result = not_found_rate_rule(self.ip, self.now, rate_threshold=0.3, min_requests=5)
        self.assertTrue(result.triggered)

    def test_sequential_id_scan_rule_detects_ordered_walk(self):
        for index, order_id in enumerate((1, 2, 3, 4, 5)):
            self.make_log(index, 200, path=f"/api/orders/{order_id}/")
        result = sequential_id_scan_rule(self.ip, self.now, run_threshold=3)
        self.assertTrue(result.triggered)
        self.assertIn("5", result.detail)

    def test_sequential_id_scan_rule_ignores_random_ids(self):
        for index, order_id in enumerate((42, 7, 19, 3, 88)):
            self.make_log(index, 200, path=f"/api/orders/{order_id}/")
        result = sequential_id_scan_rule(self.ip, self.now, run_threshold=3)
        self.assertFalse(result.triggered)


class RuleEngineTests(TestCase):
    def setUp(self):
        self.now = datetime(2026, 1, 1, tzinfo=dt_timezone.utc)
        self.ip = "203.0.113.20"

    def test_clean_request_scores_zero(self):
        evaluation = RuleEngine().evaluate(
            ip_address=self.ip, path="/api/products/", query_params={"page": "1"}, now=self.now
        )
        self.assertEqual(evaluation.score, 0.0)
        self.assertEqual(evaluation.triggered_rules, [])

    def test_injection_attempt_scores_without_any_history(self):
        evaluation = RuleEngine().evaluate(
            ip_address=self.ip,
            path="/api/products/",
            query_params={"search": "<script>alert(1)</script>"},
            now=self.now,
        )
        self.assertGreater(evaluation.score, 0.0)
        self.assertEqual(len(evaluation.triggered_rules), 1)
        self.assertEqual(evaluation.triggered_rules[0].rule, "injection_signature")

    def test_combined_signals_stack_up(self):
        for offset in range(6):
            RequestLog.objects.create(
                ip_address=self.ip,
                path="/api/auth/login/",
                method="POST",
                status_code=401,
                duration_ms=1.0,
                created_at=self.now - timedelta(seconds=offset),
            )
        evaluation = RuleEngine().evaluate(
            ip_address=self.ip,
            path="/api/products/",
            query_params={"search": "' OR '1'='1"},
            now=self.now,
        )
        triggered_names = {result.rule for result in evaluation.triggered_rules}
        self.assertIn("injection_signature", triggered_names)
        self.assertIn("unauthorized_attempts", triggered_names)
        self.assertGreater(evaluation.score, 50.0)


class ImpossibleTravelRuleTests(TestCase):
    def setUp(self):
        self.now = datetime(2026, 1, 1, 12, tzinfo=dt_timezone.utc)
        self.user_id = get_user_model().objects.create_user(username="traveler").pk
        self.locate = _fake_locate({"203.0.113.1": LONDON, "203.0.113.2": NEW_YORK})

    def make_log(self, ip_address, offset_seconds):
        RequestLog.objects.create(
            ip_address=ip_address,
            user_id=self.user_id,
            path="/api/health/",
            method="GET",
            status_code=200,
            duration_ms=1.0,
            created_at=self.now - timedelta(seconds=offset_seconds),
        )

    def test_without_a_user_or_ip_is_inert(self):
        result = impossible_travel_rule(None, "203.0.113.1", self.now, locate=self.locate)
        self.assertFalse(result.triggered)
        result = impossible_travel_rule(self.user_id, None, self.now, locate=self.locate)
        self.assertFalse(result.triggered)

    def test_a_first_request_has_nothing_to_compare_against(self):
        result = impossible_travel_rule(
            self.user_id, "203.0.113.1", self.now, locate=self.locate
        )
        self.assertFalse(result.triggered)
        self.assertEqual(result.score, 0.0)

    def test_london_to_new_york_in_ten_minutes_is_impossible(self):
        self.make_log("203.0.113.1", offset_seconds=600)  # London, 10 minutes ago

        result = impossible_travel_rule(
            self.user_id, "203.0.113.2", self.now, locate=self.locate
        )

        self.assertTrue(result.triggered)
        self.assertEqual(result.score, 100.0)

    def test_same_city_shortly_after_is_plausible(self):
        self.make_log("203.0.113.1", offset_seconds=600)  # London, 10 minutes ago
        near_london = "203.0.113.3"
        locate = _fake_locate(
            {"203.0.113.1": LONDON, "203.0.113.3": (51.51, -0.12)}  # a few km away
        )

        result = impossible_travel_rule(self.user_id, near_london, self.now, locate=locate)

        self.assertFalse(result.triggered)

    def test_unresolvable_location_does_not_trigger(self):
        self.make_log("203.0.113.1", offset_seconds=600)
        result = impossible_travel_rule(
            self.user_id, "203.0.113.9", self.now, locate=self.locate  # not in the fake map
        )
        self.assertFalse(result.triggered)
        self.assertEqual(result.score, 0.0)

    def test_ignores_requests_outside_the_window(self):
        self.make_log("203.0.113.1", offset_seconds=timedelta(hours=12).total_seconds())
        result = impossible_travel_rule(
            self.user_id, "203.0.113.2", self.now, window=timedelta(hours=6), locate=self.locate
        )
        self.assertFalse(result.triggered)


class DeviceFingerprintRuleTests(unittest.TestCase):
    def test_matching_fingerprints_do_not_trigger(self):
        result = device_fingerprint_rule("abc123", "abc123")
        self.assertFalse(result.triggered)
        self.assertEqual(result.score, 0.0)

    def test_mismatched_fingerprints_trigger(self):
        result = device_fingerprint_rule("abc123", "xyz789")
        self.assertTrue(result.triggered)
        self.assertGreater(result.score, 0.0)

    def test_missing_either_side_does_not_trigger(self):
        self.assertFalse(device_fingerprint_rule(None, "xyz789").triggered)
        self.assertFalse(device_fingerprint_rule("abc123", None).triggered)
        self.assertFalse(device_fingerprint_rule(None, None).triggered)


class RuleEngineTravelAndFingerprintTests(TestCase):
    def setUp(self):
        self.now = datetime(2026, 1, 1, 12, tzinfo=dt_timezone.utc)
        self.user_id = get_user_model().objects.create_user(username="engine-traveler").pk
        self.locate = _fake_locate({"203.0.113.1": LONDON, "203.0.113.2": NEW_YORK})

    def test_impossible_travel_is_included_in_the_combined_score(self):
        RequestLog.objects.create(
            ip_address="203.0.113.1",
            user_id=self.user_id,
            path="/api/health/",
            method="GET",
            status_code=200,
            duration_ms=1.0,
            created_at=self.now - timedelta(minutes=10),
        )
        engine = RuleEngine(locate=self.locate)

        evaluation = engine.evaluate(
            ip_address="203.0.113.2",
            path="/api/health/",
            user_id=self.user_id,
            now=self.now,
        )

        self.assertIn("impossible_travel", {r.rule for r in evaluation.triggered_rules})

    def test_device_fingerprint_mismatch_is_included_in_the_combined_score(self):
        evaluation = RuleEngine().evaluate(
            ip_address="203.0.113.50",
            path="/api/health/",
            token_fingerprint="device-a",
            request_fingerprint="device-b",
            now=self.now,
        )

        self.assertIn("device_fingerprint_mismatch", {r.rule for r in evaluation.triggered_rules})
        self.assertGreaterEqual(evaluation.score, 60.0)
