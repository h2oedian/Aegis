import unittest
from datetime import datetime, timedelta, timezone as dt_timezone

from django.test import TestCase

from aegis_core.models import RequestLog

from .engine import RuleEngine
from .rules import not_found_rate_rule, sequential_id_scan_rule, unauthorized_attempts_rule
from .signatures import scan_injection_signatures


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
