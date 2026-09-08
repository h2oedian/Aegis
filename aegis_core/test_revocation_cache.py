from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from redis.exceptions import ConnectionError as RedisConnectionError
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.test import APIRequestFactory
from rest_framework_simplejwt.tokens import RefreshToken

from .authentication import FamilyAwareJWTAuthentication
from .models import RefreshTokenRecord
from .token_denylist import is_family_revoked
from .tokens import TokenTheftDetected, issue_initial_pair, rotate_refresh_token


class RevocationCacheMissTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="cache-loss-user")
        self.redis = MagicMock()
        self.redis.exists.return_value = 0
        patcher = patch("aegis_core.token_denylist.get_redis_client", return_value=self.redis)
        patcher.start()
        self.addCleanup(patcher.stop)

    def revoke_by_reuse(self):
        initial = issue_initial_pair(self.user)
        rotated = rotate_refresh_token(initial.refresh)
        with self.assertRaises(TokenTheftDetected):
            rotate_refresh_token(initial.refresh)
        self.assertFalse(RefreshTokenRecord.objects.filter(revoked_at__isnull=True).exists())
        return rotated

    def test_cache_miss_still_finds_durable_family_revocation(self):
        rotated = self.revoke_by_reuse()
        family = RefreshToken(rotated.refresh)["family_id"]
        self.assertTrue(is_family_revoked(family))

    def test_access_token_stays_rejected_after_revocation_cache_is_lost(self):
        rotated = self.revoke_by_reuse()
        request = APIRequestFactory().get(
            "/api/health/", HTTP_AUTHORIZATION=f"Bearer {rotated.access}"
        )
        with self.assertRaises(AuthenticationFailed):
            FamilyAwareJWTAuthentication().authenticate(request)

    def test_revocation_survives_failed_cache_write_and_redis_recovery(self):
        self.redis.set.side_effect = RedisConnectionError("offline during revocation")
        rotated = self.revoke_by_reuse()
        self.redis.set.side_effect = None
        self.assertTrue(is_family_revoked(RefreshToken(rotated.refresh)["family_id"]))

    def test_cache_miss_does_not_reject_an_active_family(self):
        pair = issue_initial_pair(self.user)
        self.assertFalse(is_family_revoked(RefreshToken(pair.refresh)["family_id"]))

    def test_positive_cache_hit_needs_no_database_query(self):
        self.redis.exists.return_value = 1
        with self.assertNumQueries(0):
            self.assertTrue(is_family_revoked("cached-revoked-family"))
