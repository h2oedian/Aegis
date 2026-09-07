import csv
import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import TestCase, override_settings
from redis.exceptions import ConnectionError as RedisConnectionError

from .models import RequestLog
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
        self.assertGreaterEqual(float(fields["duration_ms"]), 0)

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

    def make_log(self, stream_id, created_at, path="/api/health/"):
        return RequestLog.objects.create(
            stream_id=stream_id,
            path=path,
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
            "attack-1", self.window_start + timedelta(seconds=65), path="/api/orders/1/"
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
