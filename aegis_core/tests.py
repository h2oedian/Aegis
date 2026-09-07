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

from .models import RequestLog
from .rate_limiter import TokenBucketRateLimiter, bucket_params_for_score
from .redis_client import get_redis_client
from .tasks import consume_request_stream


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
