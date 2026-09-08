from unittest.mock import MagicMock, patch

from django.http import HttpResponse
from django.test import RequestFactory, TestCase, override_settings

from .decision import DecisionEngine, TIER_ATTACK, TIER_RISKY
from .middleware import AdaptiveResponseMiddleware
from .serving import get_anomaly_model


class RulesOnlyFallbackTests(TestCase):
    def setUp(self):
        get_anomaly_model.cache_clear()
        self.addCleanup(get_anomaly_model.cache_clear)
        self.redis = MagicMock()
        self.redis.get.return_value = None
        self.redis.exists.return_value = 0
        self.engine = DecisionEngine(redis_client=self.redis, rule_weight=0.5)

    def attack_decision(self):
        return self.engine.decide(
            ip_address="203.0.113.95", path="/api/search/",
            query_params={"q": "UNION SELECT <script>alert(1)</script>"},
        )

    @patch("aegis_ml.serving.joblib.load", side_effect=FileNotFoundError("no trained model"))
    def test_missing_model_preserves_the_full_rule_score(self, load):
        decision = self.attack_decision()
        self.assertEqual(decision.rule_score, 100)
        self.assertEqual(decision.score, 100)
        self.assertEqual(decision.tier, TIER_ATTACK)
        self.assertEqual(decision.model_score, 0)

    @patch("aegis_ml.serving.joblib.load", side_effect=FileNotFoundError("no trained model"))
    def test_missing_model_does_not_query_features_it_cannot_score(self, load):
        with patch("aegis_ml.decision.extract_features") as features:
            self.attack_decision()
            features.assert_not_called()

    def test_without_an_ip_the_available_rules_keep_their_full_weight(self):
        decision = self.engine.decide(ip_address=None, path="/../../etc/passwd")
        self.assertEqual(decision.score, 60)
        self.assertEqual(decision.tier, TIER_RISKY)

    def test_a_loaded_model_scoring_zero_still_uses_configured_weights(self):
        model = MagicMock()
        model.score.return_value = 0.0
        with patch("aegis_ml.serving.joblib.load", return_value=model):
            decision = self.attack_decision()
        self.assertEqual(decision.score, 50)
        model.score.assert_called_once()

    def test_a_loaded_model_contributes_its_actual_score(self):
        model = MagicMock()
        model.score.return_value = 40.0
        with patch("aegis_ml.serving.joblib.load", return_value=model):
            decision = self.attack_decision()
        self.assertEqual(decision.score, 70)
        self.assertEqual(decision.model_score, 40)

    @override_settings(AEGIS_SHADOW_MODE=False)
    @patch("aegis_ml.serving.joblib.load", side_effect=FileNotFoundError("no trained model"))
    def test_enforcing_middleware_can_block_an_attack_before_a_model_is_trained(self, load):
        with patch("aegis_ml.middleware.DecisionEngine", return_value=self.engine), patch(
            "aegis_ml.middleware.TokenBucketRateLimiter"
        ):
            middleware = AdaptiveResponseMiddleware(lambda request: HttpResponse("ok"))
        request = RequestFactory().get(
            "/api/search/", {"q": "UNION SELECT <script>alert(1)</script>"},
            REMOTE_ADDR="203.0.113.95",
        )
        self.assertEqual(middleware(request).status_code, 403)
