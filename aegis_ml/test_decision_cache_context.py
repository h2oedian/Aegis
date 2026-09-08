from datetime import timedelta
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.http import HttpResponse, QueryDict
from django.test import RequestFactory, TestCase, override_settings
from django.utils import timezone

from aegis_core.models import RequestLog
from aegis_rules.engine import RuleEngine

from .decision import DecisionEngine
from .middleware import AdaptiveResponseMiddleware


class DecisionCacheContextTests(TestCase):
    def setUp(self):
        self.storage = {}
        self.redis = MagicMock()
        self.redis.get.side_effect = self.storage.get
        self.redis.set.side_effect = lambda key, value, **kwargs: self.storage.update({key: value})
        self.redis.delete.side_effect = lambda *keys: [self.storage.pop(key, None) for key in keys]
        self.engine = DecisionEngine(redis_client=self.redis, rule_weight=1.0)
        self.ip = "203.0.113.90"
        self.now = timezone.now()

    def decide(self, **kwargs):
        return self.engine.decide(
            **dict(ip_address=self.ip, path="/api/search/", now=self.now, **kwargs)
        )

    def test_clean_query_does_not_hide_a_later_injection_on_the_same_path(self):
        self.assertEqual(self.decide(query_params={"q": "hello"}).score, 0)
        self.assertEqual(
            self.decide(query_params={"q": "UNION SELECT <script>alert(1)</script>"}).score,
            100,
        )

    def test_clean_path_does_not_hide_later_path_traversal(self):
        self.assertEqual(self.engine.decide(ip_address=self.ip, path="/api/health/").score, 0)
        self.assertEqual(self.engine.decide(ip_address=self.ip, path="/../../etc/passwd").score, 60)

    def test_one_requests_signature_score_does_not_leak_to_a_clean_request(self):
        self.assertEqual(self.decide(query_params={"q": "UNION SELECT"}).score, 50)
        self.assertEqual(self.decide(query_params={"q": "hello"}).score, 0)

    def test_a_changed_request_fingerprint_is_evaluated_immediately(self):
        self.assertEqual(
            self.decide(token_fingerprint="device-a", request_fingerprint="device-a").score, 0
        )
        self.assertEqual(
            self.decide(token_fingerprint="device-a", request_fingerprint="device-b").score, 60
        )

    def test_a_changed_token_fingerprint_is_evaluated_immediately(self):
        self.decide(token_fingerprint="device-a", request_fingerprint="device-a")
        self.assertEqual(
            self.decide(token_fingerprint="device-b", request_fingerprint="device-a").score, 60
        )

    def test_users_sharing_an_ip_do_not_share_impossible_travel_verdicts(self):
        traveler = get_user_model().objects.create_user(username="traveler")
        local_user = get_user_model().objects.create_user(username="local")
        previous_ip = "198.51.100.90"
        RequestLog.objects.create(
            path="/api/health/", method="GET", status_code=200, duration_ms=1,
            ip_address=previous_ip, user=traveler, created_at=self.now - timedelta(minutes=1),
        )
        locations = {previous_ip: (51.5074, -0.1278), self.ip: (40.7128, -74.0060)}
        self.engine = DecisionEngine(
            engine=RuleEngine(locate=locations.get), redis_client=self.redis, rule_weight=1.0
        )
        self.assertEqual(self.decide(user_id=local_user.pk).score, 0)
        self.assertEqual(self.decide(user_id=traveler.pk).score, 100)

    def test_identical_requests_still_skip_rule_and_model_recomputation(self):
        with patch.object(self.engine._engine, "evaluate", wraps=self.engine._engine.evaluate) as rules:
            first = self.decide(query_params={"q": "hello"})
            with patch("aegis_ml.decision.extract_features") as features:
                self.assertEqual(self.decide(query_params={"q": "hello"}), first)
                features.assert_not_called()
            self.assertEqual(rules.call_count, 1)

    def test_duplicate_query_values_are_part_of_the_cache_context(self):
        with patch.object(self.engine._engine, "evaluate", wraps=self.engine._engine.evaluate) as rules:
            self.decide(query_params=QueryDict("q=one&q=last"))
            self.decide(query_params=QueryDict("q=two&q=last"))
            self.assertEqual(rules.call_count, 2)

    def test_cache_does_not_store_raw_request_context(self):
        self.decide(query_params={"q": "private-query-marker"}, token_fingerprint="private-device-marker")
        cached = " ".join(self.storage.values())
        self.assertNotIn("private-query-marker", cached)
        self.assertNotIn("private-device-marker", cached)

    @override_settings(AEGIS_SHADOW_MODE=False)
    def test_middleware_blocks_injection_after_a_clean_request_primes_the_cache(self):
        self.redis.exists.return_value = 0
        factory = RequestFactory()
        with patch("aegis_ml.middleware.DecisionEngine", return_value=self.engine), patch(
            "aegis_ml.middleware.TokenBucketRateLimiter"
        ):
            middleware = AdaptiveResponseMiddleware(lambda request: HttpResponse("ok"))
        clean = factory.get("/api/search/", {"q": "hello"}, REMOTE_ADDR=self.ip)
        attack = factory.get(
            "/api/search/", {"q": "UNION SELECT <script>alert(1)</script>"}, REMOTE_ADDR=self.ip
        )
        self.assertEqual(middleware(clean).status_code, 200)
        self.assertEqual(middleware(attack).status_code, 403)

    def test_unban_invalidates_the_current_cached_decision(self):
        with patch.object(self.engine._engine, "evaluate", wraps=self.engine._engine.evaluate) as rules:
            self.decide()
            self.engine.unban(self.ip)
            self.decide()
            self.assertEqual(rules.call_count, 2)

    def test_legacy_or_malformed_cache_values_are_recomputed(self):
        for raw in ('{"score": 99, "tier": "attack", "rule_score": 99, "model_score": 0}', "{broken"):
            with self.subTest(raw=raw):
                self.storage[f"aegis:decision:{self.ip}"] = raw
                self.assertEqual(self.decide().score, 0)
