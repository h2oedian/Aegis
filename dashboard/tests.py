import unittest
from datetime import datetime, timedelta, timezone as dt_timezone
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from aegis_core.models import AuditLog, RequestLog

from .metrics import build_snapshot, request_volume_by_minute


class RequestVolumeByMinuteTests(TestCase):
    def setUp(self):
        self.now = datetime(2026, 1, 1, 12, 30, tzinfo=dt_timezone.utc)

    def make_log(self, minutes_ago, count=1):
        for _ in range(count):
            RequestLog.objects.create(
                path="/api/health/",
                method="GET",
                status_code=200,
                duration_ms=1.0,
                created_at=self.now - timedelta(minutes=minutes_ago),
            )

    def test_zero_fills_minutes_with_no_traffic(self):
        points = request_volume_by_minute(minutes=5, now=self.now)
        self.assertEqual(len(points), 6)
        self.assertTrue(all(point.count == 0 for point in points))
        self.assertTrue(all(point.height_percent == 0.0 for point in points))

    def test_counts_requests_into_the_right_minute_bucket(self):
        self.make_log(minutes_ago=2, count=3)
        self.make_log(minutes_ago=0, count=1)

        points = request_volume_by_minute(minutes=5, now=self.now)

        counts = {point.minute: point.count for point in points}
        busy_minute = self.now.replace(second=0, microsecond=0) - timedelta(minutes=2)
        self.assertEqual(counts[busy_minute], 3)

    def test_height_percent_is_relative_to_the_busiest_minute(self):
        self.make_log(minutes_ago=3, count=4)
        self.make_log(minutes_ago=1, count=2)

        points = request_volume_by_minute(minutes=5, now=self.now)

        heights = {point.count: point.height_percent for point in points if point.count}
        self.assertEqual(heights[4], 100.0)
        self.assertEqual(heights[2], 50.0)

    def test_ignores_requests_outside_the_window(self):
        self.make_log(minutes_ago=60)
        points = request_volume_by_minute(minutes=5, now=self.now)
        self.assertEqual(sum(point.count for point in points), 0)


class BuildSnapshotTests(TestCase):
    def setUp(self):
        self.now = datetime(2026, 1, 1, 12, 30, tzinfo=dt_timezone.utc)
        self.ip = "203.0.113.90"

    def test_a_noisy_ip_shows_up_as_risky_with_its_triggered_rule(self):
        for offset in range(6):
            RequestLog.objects.create(
                ip_address=self.ip,
                path="/api/auth/login/",
                method="POST",
                status_code=401,
                duration_ms=1.0,
                created_at=self.now - timedelta(seconds=offset),
            )

        snapshot = build_snapshot(window_minutes=30, top_ips=10, now=self.now)

        risky_ips = {entry.ip_address: entry for entry in snapshot.risky_ips}
        self.assertIn(self.ip, risky_ips)
        self.assertIn("unauthorized_attempts", risky_ips[self.ip].triggered_rules)
        self.assertEqual(risky_ips[self.ip].request_count, 6)
        breakdown = dict(snapshot.rule_breakdown)
        self.assertEqual(breakdown.get("unauthorized_attempts"), 1)

    def test_a_quiet_ip_is_not_flagged(self):
        RequestLog.objects.create(
            ip_address="203.0.113.91",
            path="/api/health/",
            method="GET",
            status_code=200,
            duration_ms=1.0,
            created_at=self.now,
        )

        snapshot = build_snapshot(window_minutes=30, top_ips=10, now=self.now)

        self.assertEqual(snapshot.risky_ips, [])

    def test_includes_recent_audit_events(self):
        AuditLog.objects.create(
            event_type="attack_blocked",
            payload={"ip_address": "203.0.113.92"},
            created_at=self.now,
            previous_hash="0" * 64,
            hash="a" * 64,
        )

        snapshot = build_snapshot(now=self.now)

        self.assertEqual(len(snapshot.recent_events), 1)
        self.assertEqual(snapshot.recent_events[0].event_type, "attack_blocked")

    def test_marks_a_banned_ip(self):
        for offset in range(6):
            RequestLog.objects.create(
                ip_address=self.ip,
                path="/api/auth/login/",
                method="POST",
                status_code=401,
                duration_ms=1.0,
                created_at=self.now - timedelta(seconds=offset),
            )

        fake_decisions = MagicMock()
        fake_decisions.is_banned.return_value = True
        snapshot = build_snapshot(now=self.now, decisions=fake_decisions)

        risky_ips = {entry.ip_address: entry for entry in snapshot.risky_ips}
        self.assertTrue(risky_ips[self.ip].banned)


class DashboardAccessTests(TestCase):
    def test_anonymous_users_are_redirected_to_login(self):
        response = self.client.get(reverse("dashboard:index"))
        self.assertEqual(response.status_code, 302)

    def test_non_staff_users_are_redirected_to_login(self):
        user = get_user_model().objects.create_user(username="regular", password="pw", is_staff=False)
        self.client.force_login(user)
        response = self.client.get(reverse("dashboard:index"))
        self.assertEqual(response.status_code, 302)

    def test_staff_users_can_view_the_dashboard(self):
        staff = get_user_model().objects.create_user(username="staffer", password="pw", is_staff=True)
        self.client.force_login(staff)
        response = self.client.get(reverse("dashboard:index"))
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Request volume", response.content)


class DashboardPartialTests(TestCase):
    def setUp(self):
        self.staff = get_user_model().objects.create_user(
            username="partial-staff", password="pw", is_staff=True
        )
        self.client.force_login(self.staff)

    def test_volume_partial_renders(self):
        response = self.client.get(reverse("dashboard:volume-partial"))
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"volume-chart", response.content)

    def test_risky_ips_partial_renders(self):
        response = self.client.get(reverse("dashboard:risky-ips-partial"))
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"risky-ips", response.content)

    def test_events_partial_renders(self):
        response = self.client.get(reverse("dashboard:events-partial"))
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"recent-events", response.content)


class BanUnbanViewTests(TestCase):
    def setUp(self):
        self.staff = get_user_model().objects.create_user(
            username="ban-staff", password="pw", is_staff=True
        )
        self.client.force_login(self.staff)

    def test_ban_calls_the_decision_engine_and_records_an_audit_event(self):
        with patch("dashboard.views.DecisionEngine") as decision_engine_cls:
            response = self.client.post(reverse("dashboard:ban"), {"ip_address": "203.0.113.99"})

        decision_engine_cls.return_value.ban.assert_called_once_with("203.0.113.99")
        self.assertEqual(response.status_code, 302)
        event = AuditLog.objects.get(event_type="manual_ban")
        self.assertEqual(event.payload["ip_address"], "203.0.113.99")
        self.assertEqual(event.payload["staff_user"], "ban-staff")

    def test_unban_calls_the_decision_engine_and_records_an_audit_event(self):
        with patch("dashboard.views.DecisionEngine") as decision_engine_cls:
            response = self.client.post(reverse("dashboard:unban"), {"ip_address": "203.0.113.99"})

        decision_engine_cls.return_value.unban.assert_called_once_with("203.0.113.99")
        self.assertEqual(response.status_code, 302)
        self.assertTrue(AuditLog.objects.filter(event_type="manual_unban").exists())

    def test_ban_without_an_ip_address_does_nothing(self):
        with patch("dashboard.views.DecisionEngine") as decision_engine_cls:
            self.client.post(reverse("dashboard:ban"), {})
        decision_engine_cls.return_value.ban.assert_not_called()
        self.assertFalse(AuditLog.objects.filter(event_type="manual_ban").exists())

    def test_ban_rejects_get_requests(self):
        response = self.client.get(reverse("dashboard:ban"))
        self.assertEqual(response.status_code, 405)


if __name__ == "__main__":
    unittest.main()
