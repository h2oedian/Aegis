import csv
import json
import tempfile
import threading
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import TestCase, override_settings
from redis import Redis
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import RedisError
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.test import APIRequestFactory
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken

from .authentication import FamilyAwareJWTAuthentication
from .fingerprint import compute_fingerprint
from .geoip import haversine_km, locate_ip
from .models import RefreshTokenRecord, RequestLog
from .rate_limiter import TokenBucketRateLimiter, bucket_params_for_score
from .redis_client import get_redis_client
from .tasks import consume_request_stream
from .token_denylist import deny_family, deny_jti, is_family_revoked, is_jti_denied
from .tokens import (
    TokenTheftDetected,
    issue_initial_pair,
    peek_access_token,
    rotate_refresh_token,
)


class RequestTelemetryMiddlewareTests(TestCase):
    def setUp(self):
        redis_patcher = patch("aegis_core.middleware.get_redis_client")
        self.addCleanup(redis_patcher.stop)
        self.redis_client = redis_patcher.start().return_value

    def published_fields(self):
        return self.redis_client.xadd.call_args.args[1]

    def test_publishes_anonymous_request_metadata(self):
        response = self.client.get(
            "/api/health/",
            REMOTE_ADDR="203.0.113.10",
            HTTP_USER_AGENT="Aegis test client",
        )
        self.assertEqual(response.status_code, 200)
        fields = self.published_fields()
        self.assertEqual(fields["path"], "/api/health/")
        self.assertEqual(fields["method"], "GET")
        self.assertEqual(fields["status_code"], "200")
        self.assertEqual(fields["ip_address"], "203.0.113.10")
        self.assertEqual(fields["user_agent"], "Aegis test client")
        self.assertEqual(fields["user_id"], "")
        self.assertEqual(fields["query_string"], "")
        self.assertGreaterEqual(float(fields["duration_ms"]), 0)

    def test_publishes_query_string(self):
        self.client.get("/api/health/?search=%27+OR+%271%27%3D%271&page=2")
        self.assertEqual(
            self.published_fields()["query_string"], "search=%27+OR+%271%27%3D%271&page=2"
        )

    def test_publishes_authenticated_session_user_id(self):
        user = get_user_model().objects.create_user(
            username="telemetry-user", password="safe-test-password"
        )
        self.client.force_login(user)
        self.client.get("/api/health/")
        self.assertEqual(self.published_fields()["user_id"], str(user.pk))

    def test_truncates_oversized_user_agent(self):
        self.client.get("/api/health/", HTTP_USER_AGENT="x" * 2048)
        self.assertEqual(len(self.published_fields()["user_agent"]), 1024)

    def test_does_not_trust_forwarded_ip_by_default(self):
        self.client.get(
            "/api/health/",
            REMOTE_ADDR="192.0.2.20",
            HTTP_X_FORWARDED_FOR="203.0.113.50, 10.0.0.1",
        )
        self.assertEqual(self.published_fields()["ip_address"], "192.0.2.20")

    @override_settings(AEGIS_TRUST_PROXY_HEADERS=True)
    def test_uses_first_forwarded_ip_when_proxy_headers_are_trusted(self):
        self.client.get(
            "/api/health/",
            REMOTE_ADDR="192.0.2.20",
            HTTP_X_FORWARDED_FOR="203.0.113.50, 10.0.0.1",
        )
        self.assertEqual(self.published_fields()["ip_address"], "203.0.113.50")

    def test_fails_open_when_redis_is_unavailable(self):
        self.redis_client.xadd.side_effect = RedisConnectionError("offline")
        with self.assertLogs("aegis_core.middleware", level="WARNING"):
            response = self.client.get("/api/health/")
        self.assertEqual(response.status_code, 200)


class RequestStreamConsumerTests(TestCase):
    @patch("aegis_core.tasks.get_redis_client")
    def test_persists_batch_then_acknowledges_messages(self, get_redis_client):
        user = get_user_model().objects.create_user(username="stream-user")
        redis_client = MagicMock()
        get_redis_client.return_value = redis_client
        redis_client.xautoclaim.return_value = ("0-0", [], [])
        redis_client.xreadgroup.return_value = [
            (
                "aegis:requests",
                [
                    (
                        "1757145600000-0",
                        {
                            "occurred_at_ms": "1757145600000",
                            "path": "/api/orders/1/",
                            "query_string": "search=%27+OR+%271%27%3D%271",
                            "method": "GET",
                            "status_code": "200",
                            "duration_ms": "1.25",
                            "ip_address": "203.0.113.10",
                            "user_agent": "consumer test",
                            "user_id": str(user.pk),
                            "token_jti": "token-id",
                        },
                    )
                ],
            )
        ]
        consumed = consume_request_stream.run()
        self.assertEqual(consumed, 1)
        request_log = RequestLog.objects.get(stream_id="1757145600000-0")
        self.assertEqual(request_log.path, "/api/orders/1/")
        self.assertEqual(request_log.query_string, "search=%27+OR+%271%27%3D%271")
        self.assertEqual(request_log.user, user)
        self.assertEqual(request_log.token_jti, "token-id")
        redis_client.xack.assert_called_once_with(
            "aegis:requests", "aegis-request-loggers", "1757145600000-0"
        )

    @patch("aegis_core.tasks.get_redis_client")
    def test_duplicate_stream_message_is_idempotent(self, get_redis_client):
        fields = {
            "occurred_at_ms": "1757145600000",
            "path": "/api/health/",
            "method": "GET",
            "status_code": "200",
            "duration_ms": "0.5",
            "ip_address": "",
            "user_agent": "",
            "user_id": "",
            "token_jti": "",
        }
        redis_client = MagicMock()
        get_redis_client.return_value = redis_client
        redis_client.xautoclaim.return_value = ("0-0", [], [])
        redis_client.xreadgroup.return_value = [
            ("aegis:requests", [("1757145600000-1", fields)])
        ]
        consume_request_stream.run()
        consume_request_stream.run()
        self.assertEqual(
            RequestLog.objects.filter(stream_id="1757145600000-1").count(), 1
        )

    @patch("aegis_core.tasks.get_redis_client")
    def test_reclaims_abandoned_pending_message(self, get_redis_client):
        fields = {
            "occurred_at_ms": "1757145600000",
            "path": "/api/recovered/",
            "method": "GET",
            "status_code": "200",
            "duration_ms": "0.75",
            "ip_address": "",
            "user_agent": "",
            "user_id": "",
            "token_jti": "",
        }
        redis_client = MagicMock()
        get_redis_client.return_value = redis_client
        redis_client.xautoclaim.return_value = (
            "0-0",
            [("1757145600000-2", fields)],
            [],
        )

        consumed = consume_request_stream.run()

        self.assertEqual(consumed, 1)
        self.assertTrue(
            RequestLog.objects.filter(stream_id="1757145600000-2").exists()
        )
        redis_client.xreadgroup.assert_not_called()


class LabelRequestDatasetCommandTests(TestCase):
    def setUp(self):
        self.window_start = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def make_log(self, stream_id, created_at, path="/api/health/", query_string=""):
        return RequestLog.objects.create(
            stream_id=stream_id,
            path=path,
            query_string=query_string,
            method="GET",
            status_code=200,
            duration_ms=1.5,
            created_at=created_at,
        )

    def write_manifest(self, windows):
        manifest_path = Path(tempfile.mkdtemp()) / "manifest.json"
        manifest_path.write_text(json.dumps(windows), encoding="utf-8")
        return manifest_path

    def test_labels_rows_by_campaign_window(self):
        self.make_log(
            "normal-1", self.window_start + timedelta(seconds=5), path="/api/products/"
        )
        self.make_log(
            "attack-1",
            self.window_start + timedelta(seconds=65),
            path="/api/orders/1/",
            query_string="search=%27+OR+%271%27%3D%271",
        )
        manifest = self.write_manifest(
            [
                {
                    "label": "normal",
                    "scenario": "normal-traffic",
                    "started_at": self.window_start.isoformat(),
                    "ended_at": (self.window_start + timedelta(seconds=60)).isoformat(),
                },
                {
                    "label": "attack",
                    "scenario": "id-enumeration",
                    "started_at": (self.window_start + timedelta(seconds=60)).isoformat(),
                    "ended_at": (self.window_start + timedelta(seconds=120)).isoformat(),
                },
            ]
        )
        output_path = manifest.parent / "dataset.csv"

        call_command(
            "label_request_dataset",
            manifest=str(manifest),
            output=str(output_path),
        )

        with open(output_path, newline="", encoding="utf-8") as csv_file:
            rows = list(csv.DictReader(csv_file))

        self.assertEqual(len(rows), 2)
        by_path = {row["path"]: row for row in rows}
        self.assertEqual(by_path["/api/products/"]["label"], "normal")
        self.assertEqual(by_path["/api/orders/1/"]["label"], "attack")
        self.assertEqual(by_path["/api/orders/1/"]["scenario"], "id-enumeration")
        self.assertEqual(
            by_path["/api/orders/1/"]["query_string"], "search=%27+OR+%271%27%3D%271"
        )

    def test_rows_outside_every_window_are_excluded(self):
        self.make_log("in-window", self.window_start + timedelta(seconds=5))
        self.make_log("outside-window", self.window_start + timedelta(hours=2))
        manifest = self.write_manifest(
            [
                {
                    "label": "normal",
                    "scenario": "normal-traffic",
                    "started_at": self.window_start.isoformat(),
                    "ended_at": (self.window_start + timedelta(seconds=60)).isoformat(),
                }
            ]
        )
        output_path = manifest.parent / "dataset.csv"

        call_command(
            "label_request_dataset",
            manifest=str(manifest),
            output=str(output_path),
        )

        with open(output_path, newline="", encoding="utf-8") as csv_file:
            rows = list(csv.DictReader(csv_file))
        self.assertEqual(len(rows), 1)


class RiskScoreBucketParamsTests(unittest.TestCase):
    def test_zero_score_uses_the_full_bucket(self):
        capacity, refill_rate = bucket_params_for_score(
            0,
            base_capacity=60,
            base_refill_per_second=1,
            min_capacity=3,
            min_refill_per_second=0.05,
        )
        self.assertEqual(capacity, 60)
        self.assertEqual(refill_rate, 1)

    def test_max_score_shrinks_to_the_minimum(self):
        capacity, refill_rate = bucket_params_for_score(
            100,
            base_capacity=60,
            base_refill_per_second=1,
            min_capacity=3,
            min_refill_per_second=0.05,
        )
        self.assertAlmostEqual(capacity, 3)
        self.assertAlmostEqual(refill_rate, 0.05)

    def test_score_is_clamped_to_the_valid_range(self):
        kwargs = dict(base_capacity=60, base_refill_per_second=1, min_capacity=3, min_refill_per_second=0.05)
        below_range, _ = bucket_params_for_score(-50, **kwargs)
        at_zero, _ = bucket_params_for_score(0, **kwargs)
        above_range, _ = bucket_params_for_score(500, **kwargs)
        at_hundred, _ = bucket_params_for_score(100, **kwargs)
        self.assertEqual(below_range, at_zero)
        self.assertEqual(above_range, at_hundred)


class TokenBucketRateLimiterFailOpenTests(TestCase):
    def test_fails_open_when_redis_is_unavailable(self):
        redis_client = MagicMock()
        redis_client.register_script.return_value = MagicMock(
            side_effect=RedisConnectionError("offline")
        )
        limiter = TokenBucketRateLimiter(redis_client=redis_client)

        with self.assertLogs("aegis_core.rate_limiter", level="WARNING"):
            decision = limiter.check("ip:203.0.113.10", capacity=10, refill_rate=1)

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.remaining_tokens, 10)


def _redis_reachable():
    try:
        return Redis.from_url(settings.REDIS_URL, socket_connect_timeout=0.2).ping()
    except RedisError:
        return False


@unittest.skipUnless(_redis_reachable(), "Redis is not reachable from this environment")
class TokenBucketRateLimiterLiveTests(TestCase):
    """Exercises the Lua script against a real Redis; the atomicity claim
    that matters here can't be verified against a mock."""

    def setUp(self):
        self.redis_client = get_redis_client()
        self.limiter = TokenBucketRateLimiter(
            redis_client=self.redis_client, key_prefix="aegis:test:ratelimit:"
        )
        self.key = f"live-{uuid.uuid4()}"

    def tearDown(self):
        self.redis_client.delete(f"aegis:test:ratelimit:{self.key}")

    def test_allows_up_to_capacity_then_blocks(self):
        for _ in range(3):
            decision = self.limiter.check(self.key, capacity=3, refill_rate=0.0001, now=1_000.0)
            self.assertTrue(decision.allowed)

        blocked = self.limiter.check(self.key, capacity=3, refill_rate=0.0001, now=1_000.0)
        self.assertFalse(blocked.allowed)

    def test_tokens_refill_over_time(self):
        self.limiter.check(self.key, capacity=1, refill_rate=1.0, now=1_000.0)
        still_empty = self.limiter.check(self.key, capacity=1, refill_rate=1.0, now=1_000.5)
        self.assertFalse(still_empty.allowed)

        refilled = self.limiter.check(self.key, capacity=1, refill_rate=1.0, now=1_001.1)
        self.assertTrue(refilled.allowed)

    def test_concurrent_requests_never_exceed_capacity(self):
        allowed_flags = []

        def hit():
            decision = self.limiter.check(self.key, capacity=5, refill_rate=0.0001, now=2_000.0)
            allowed_flags.append(decision.allowed)

        threads = [threading.Thread(target=hit) for _ in range(20)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(sum(allowed_flags), 5)


class TokenRotationTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="token-user", password="safe-test-password"
        )

    def test_issuing_the_initial_pair_creates_a_refresh_token_record(self):
        pair = issue_initial_pair(self.user)

        jti = str(RefreshToken(pair.refresh)["jti"])
        record = RefreshTokenRecord.objects.get(jti=jti)
        self.assertEqual(record.user, self.user)
        self.assertIsNone(record.used_at)
        self.assertIsNone(record.revoked_at)

    def test_rotating_marks_the_old_token_used_and_issues_a_new_one(self):
        initial = issue_initial_pair(self.user)
        old_jti = str(RefreshToken(initial.refresh)["jti"])

        rotated = rotate_refresh_token(initial.refresh)

        old_record = RefreshTokenRecord.objects.get(jti=old_jti)
        self.assertIsNotNone(old_record.used_at)
        new_jti = str(RefreshToken(rotated.refresh)["jti"])
        self.assertNotEqual(new_jti, old_jti)
        self.assertTrue(RefreshTokenRecord.objects.filter(jti=new_jti).exists())

    def test_rotated_tokens_share_the_same_family(self):
        initial = issue_initial_pair(self.user)
        old_family = RefreshToken(initial.refresh).payload["family_id"]

        rotated = rotate_refresh_token(initial.refresh)

        new_family = RefreshToken(rotated.refresh).payload["family_id"]
        self.assertEqual(new_family, old_family)

    def test_reusing_a_refresh_token_is_detected_as_theft(self):
        initial = issue_initial_pair(self.user)
        rotate_refresh_token(initial.refresh)  # legitimate rotation

        with self.assertRaises(TokenTheftDetected):
            rotate_refresh_token(initial.refresh)  # someone replays the old one

    def test_theft_revokes_every_outstanding_token_in_the_family(self):
        first_login = issue_initial_pair(self.user)
        family_id = RefreshToken(first_login.refresh).payload["family_id"]
        # A second, still-unused token in the same family (e.g. another device).
        RefreshToken.for_user(self.user)
        RefreshTokenRecord.objects.create(
            jti="second-device-jti",
            family_id=family_id,
            user=self.user,
            expires_at=datetime.now(timezone.utc) + timedelta(days=1),
        )
        rotate_refresh_token(first_login.refresh)

        with self.assertRaises(TokenTheftDetected):
            rotate_refresh_token(first_login.refresh)  # trigger theft detection

        second_device_record = RefreshTokenRecord.objects.get(jti="second-device-jti")
        self.assertIsNotNone(second_device_record.revoked_at)

    def test_a_revoked_family_rejects_a_token_that_was_never_reused(self):
        first_login = issue_initial_pair(self.user)
        rotated = rotate_refresh_token(first_login.refresh)
        with self.assertRaises(TokenTheftDetected):
            rotate_refresh_token(first_login.refresh)  # detect theft, revoke the family

        with self.assertRaises(TokenTheftDetected):
            rotate_refresh_token(rotated.refresh)  # never reused, but its family is dead

    def test_an_unknown_but_validly_signed_token_is_treated_as_theft(self):
        forged = RefreshToken.for_user(self.user)
        forged["family_id"] = "not-in-the-database"

        with self.assertRaises(TokenTheftDetected):
            rotate_refresh_token(str(forged))

    def test_a_token_missing_the_family_claim_is_rejected(self):
        bare = RefreshToken.for_user(self.user)

        with self.assertRaises(TokenTheftDetected):
            rotate_refresh_token(str(bare))


class _FakeRedis:
    """Minimal in-memory stand-in for the get/set/exists the denylist uses,
    for tests that need real cross-call round-trip behaviour without a
    live Redis server."""

    def __init__(self):
        self._store = {}

    def set(self, key, value, ex=None):
        self._store[key] = value
        return True

    def get(self, key):
        return self._store.get(key)

    def exists(self, key):
        return 1 if key in self._store else 0


def _use_fake_denylist_redis(test_case):
    fake = _FakeRedis()
    patcher = patch("aegis_core.token_denylist.get_redis_client", return_value=fake)
    test_case.addCleanup(patcher.stop)
    patcher.start()
    return fake


class TokenDenylistTests(TestCase):
    def test_deny_and_check_jti_round_trip(self):
        _use_fake_denylist_redis(self)
        deny_jti("some-jti")
        self.assertTrue(is_jti_denied("some-jti"))
        self.assertFalse(is_jti_denied("a-different-jti"))

    def test_deny_and_check_family_round_trip(self):
        _use_fake_denylist_redis(self)
        deny_family("some-family")
        self.assertTrue(is_family_revoked("some-family"))
        self.assertFalse(is_family_revoked("a-different-family"))

    def test_is_jti_denied_fails_open_when_redis_is_unavailable(self):
        with patch("aegis_core.token_denylist.get_redis_client") as get_client:
            get_client.return_value.exists.side_effect = RedisConnectionError("offline")
            self.assertFalse(is_jti_denied("whatever"))

    def test_is_family_revoked_falls_back_to_the_database_when_redis_is_unavailable(self):
        user = get_user_model().objects.create_user(username="denylist-user")
        RefreshTokenRecord.objects.create(
            jti="db-only-jti",
            family_id="db-only-family",
            user=user,
            expires_at=datetime.now(timezone.utc) + timedelta(days=1),
            revoked_at=datetime.now(timezone.utc),
        )

        with patch("aegis_core.token_denylist.get_redis_client") as get_client:
            get_client.return_value.exists.side_effect = RedisConnectionError("offline")
            self.assertTrue(is_family_revoked("db-only-family"))
            self.assertFalse(is_family_revoked("some-other-family"))


class FamilyAwareJWTAuthenticationTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="auth-user", password="safe-test-password"
        )
        self.auth = FamilyAwareJWTAuthentication()
        self.factory = APIRequestFactory()
        _use_fake_denylist_redis(self)

    def _request_with_token(self, access_token):
        return self.factory.get("/api/health/", HTTP_AUTHORIZATION=f"Bearer {access_token}")

    def test_accepts_a_normal_access_token(self):
        pair = issue_initial_pair(self.user)
        request = self._request_with_token(pair.access)

        user, token = self.auth.authenticate(request)

        self.assertEqual(user, self.user)
        self.assertEqual(str(token["jti"]), str(AccessToken(pair.access)["jti"]))

    def test_rejects_an_access_token_whose_family_was_revoked(self):
        pair = issue_initial_pair(self.user)
        family_id = RefreshToken(pair.refresh).payload["family_id"]
        deny_family(family_id)

        request = self._request_with_token(pair.access)
        with self.assertRaises(AuthenticationFailed):
            self.auth.authenticate(request)

    def test_rejects_a_directly_denied_access_token(self):
        pair = issue_initial_pair(self.user)
        access_jti = str(AccessToken(pair.access)["jti"])
        deny_jti(access_jti)

        request = self._request_with_token(pair.access)
        with self.assertRaises(AuthenticationFailed):
            self.auth.authenticate(request)


class AuthEndpointTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="endpoint-user", password="correct-horse-battery-staple"
        )

    def test_login_returns_a_token_pair_for_valid_credentials(self):
        response = self.client.post(
            "/api/auth/login/",
            {"username": "endpoint-user", "password": "correct-horse-battery-staple"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("refresh", response.json())
        self.assertIn("access", response.json())

    def test_login_rejects_invalid_credentials(self):
        response = self.client.post(
            "/api/auth/login/", {"username": "endpoint-user", "password": "wrong"}
        )
        self.assertEqual(response.status_code, 401)

    def test_refresh_rotates_and_returns_a_new_pair(self):
        pair = issue_initial_pair(self.user)

        response = self.client.post("/api/auth/refresh/", {"refresh": pair.refresh})

        self.assertEqual(response.status_code, 200)
        self.assertNotEqual(response.json()["refresh"], pair.refresh)

    def test_refresh_rejects_a_reused_token(self):
        pair = issue_initial_pair(self.user)
        self.client.post("/api/auth/refresh/", {"refresh": pair.refresh})

        response = self.client.post("/api/auth/refresh/", {"refresh": pair.refresh})

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["error"], "token_reuse_detected")

    def test_refresh_requires_a_refresh_field(self):
        response = self.client.post("/api/auth/refresh/", {})
        self.assertEqual(response.status_code, 400)

    def test_health_endpoint_records_the_access_token_jti_in_telemetry(self):
        pair = issue_initial_pair(self.user)
        access_jti = str(AccessToken(pair.access)["jti"])

        redis_patcher = patch("aegis_core.middleware.get_redis_client")
        self.addCleanup(redis_patcher.stop)
        redis_client = redis_patcher.start().return_value

        response = self.client.get(
            "/api/health/", HTTP_AUTHORIZATION=f"Bearer {pair.access}"
        )

        self.assertEqual(response.status_code, 200)
        published_fields = redis_client.xadd.call_args.args[1]
        self.assertEqual(published_fields["token_jti"], access_jti)
        self.assertEqual(published_fields["user_id"], str(self.user.pk))

    def test_health_endpoint_rejects_an_access_token_from_a_revoked_family(self):
        _use_fake_denylist_redis(self)
        pair = issue_initial_pair(self.user)
        family_id = RefreshToken(pair.refresh).payload["family_id"]
        deny_family(family_id)

        response = self.client.get(
            "/api/health/", HTTP_AUTHORIZATION=f"Bearer {pair.access}"
        )

        self.assertEqual(response.status_code, 401)


class FingerprintTests(TestCase):
    def _request(self, *, user_agent="curl/8.0", accept_language="en-US", accept_encoding="gzip"):
        return APIRequestFactory().get(
            "/api/health/",
            HTTP_USER_AGENT=user_agent,
            HTTP_ACCEPT_LANGUAGE=accept_language,
            HTTP_ACCEPT_ENCODING=accept_encoding,
        )

    def test_same_headers_produce_the_same_fingerprint(self):
        self.assertEqual(
            compute_fingerprint(self._request()), compute_fingerprint(self._request())
        )

    def test_different_user_agents_produce_different_fingerprints(self):
        self.assertNotEqual(
            compute_fingerprint(self._request(user_agent="curl/8.0")),
            compute_fingerprint(self._request(user_agent="python-requests/2.0")),
        )

    def test_fingerprint_is_a_sha256_hex_digest(self):
        fingerprint = compute_fingerprint(self._request())
        self.assertEqual(len(fingerprint), 64)
        int(fingerprint, 16)  # raises ValueError if it isn't hex


class GeoIPTests(TestCase):
    def test_haversine_distance_between_known_cities(self):
        london = (51.5074, -0.1278)
        paris = (48.8566, 2.3522)
        distance_km = haversine_km(*london, *paris)
        self.assertAlmostEqual(distance_km, 344, delta=10)

    def test_haversine_distance_to_self_is_zero(self):
        point = (35.6892, 51.3890)
        self.assertAlmostEqual(haversine_km(*point, *point), 0.0, places=6)

    @override_settings(AEGIS_GEOIP_DB_PATH="")
    def test_locate_ip_returns_none_without_a_configured_database(self):
        self.assertIsNone(locate_ip("8.8.8.8"))

    def test_locate_ip_returns_none_for_a_missing_ip(self):
        self.assertIsNone(locate_ip(None))


class PeekAccessTokenTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="peek-user")

    def test_returns_the_user_id_and_fingerprint_from_a_valid_token(self):
        pair = issue_initial_pair(self.user, fingerprint="device-abc")

        peeked = peek_access_token(f"Bearer {pair.access}")

        self.assertEqual(peeked.user_id, self.user.pk)
        self.assertEqual(peeked.fingerprint, "device-abc")

    def test_returns_none_for_a_missing_bearer_prefix(self):
        pair = issue_initial_pair(self.user)
        self.assertIsNone(peek_access_token(pair.access))

    def test_returns_none_for_an_empty_header(self):
        self.assertIsNone(peek_access_token(""))

    def test_returns_none_for_a_garbage_token(self):
        self.assertIsNone(peek_access_token("Bearer not-a-real-token"))


class TokenFingerprintBindingTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="bind-user")

    def test_initial_issuance_stores_the_fingerprint(self):
        pair = issue_initial_pair(self.user, fingerprint="device-xyz")

        jti = str(RefreshToken(pair.refresh)["jti"])
        record = RefreshTokenRecord.objects.get(jti=jti)
        self.assertEqual(record.fingerprint, "device-xyz")
        self.assertEqual(AccessToken(pair.access).payload.get("fingerprint"), "device-xyz")

    def test_rotation_carries_the_fingerprint_forward_unchanged(self):
        initial = issue_initial_pair(self.user, fingerprint="device-xyz")

        rotated = rotate_refresh_token(initial.refresh)

        new_jti = str(RefreshToken(rotated.refresh)["jti"])
        new_record = RefreshTokenRecord.objects.get(jti=new_jti)
        self.assertEqual(new_record.fingerprint, "device-xyz")
        self.assertEqual(AccessToken(rotated.access).payload.get("fingerprint"), "device-xyz")
