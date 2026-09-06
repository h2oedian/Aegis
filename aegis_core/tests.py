from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings

from .models import RequestLog


class RequestTelemetryMiddlewareTests(TestCase):
    def test_logs_anonymous_request_metadata(self):
        response = self.client.get(
            "/api/health/",
            REMOTE_ADDR="203.0.113.10",
            HTTP_USER_AGENT="Aegis test client",
        )

        self.assertEqual(response.status_code, 200)
        request_log = RequestLog.objects.get()
        self.assertEqual(request_log.path, "/api/health/")
        self.assertEqual(request_log.method, "GET")
        self.assertEqual(request_log.status_code, 200)
        self.assertEqual(request_log.ip_address, "203.0.113.10")
        self.assertEqual(request_log.user_agent, "Aegis test client")
        self.assertIsNone(request_log.user)
        self.assertGreaterEqual(request_log.duration_ms, 0)

    def test_logs_authenticated_session_user(self):
        user = get_user_model().objects.create_user(
            username="telemetry-user", password="safe-test-password"
        )
        self.client.force_login(user)

        self.client.get("/api/health/")

        self.assertEqual(RequestLog.objects.get().user, user)

    def test_truncates_oversized_user_agent(self):
        self.client.get("/api/health/", HTTP_USER_AGENT="x" * 2048)

        self.assertEqual(len(RequestLog.objects.get().user_agent), 1024)

    def test_does_not_trust_forwarded_ip_by_default(self):
        self.client.get(
            "/api/health/",
            REMOTE_ADDR="192.0.2.20",
            HTTP_X_FORWARDED_FOR="203.0.113.50, 10.0.0.1",
        )

        self.assertEqual(RequestLog.objects.get().ip_address, "192.0.2.20")

    @override_settings(AEGIS_TRUST_PROXY_HEADERS=True)
    def test_uses_first_forwarded_ip_when_proxy_headers_are_trusted(self):
        self.client.get(
            "/api/health/",
            REMOTE_ADDR="192.0.2.20",
            HTTP_X_FORWARDED_FOR="203.0.113.50, 10.0.0.1",
        )

        self.assertEqual(RequestLog.objects.get().ip_address, "203.0.113.50")
