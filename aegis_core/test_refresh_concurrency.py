import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from unittest import skipUnless
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.db import close_old_connections, connection, connections, transaction
from django.test import TestCase, TransactionTestCase
from rest_framework_simplejwt.tokens import RefreshToken

from .models import RefreshTokenRecord
from .tokens import TokenTheftDetected, issue_initial_pair, rotate_refresh_token


class RotationRollbackTests(TestCase):
    def test_failed_successor_issuance_does_not_consume_or_deny_the_original(self):
        user = get_user_model().objects.create_user(username="rotation-rollback")
        initial = issue_initial_pair(user)
        jti = RefreshToken(initial.refresh)["jti"]
        with patch("aegis_core.tokens.is_jti_denied", return_value=False), patch(
            "aegis_core.tokens.is_family_revoked", return_value=False
        ), patch("aegis_core.tokens.deny_jti") as deny, patch(
            "aegis_core.tokens._issue_pair", side_effect=RuntimeError("issuance failed")
        ):
            with self.assertRaisesRegex(RuntimeError, "issuance failed"):
                rotate_refresh_token(initial.refresh)
        self.assertIsNone(RefreshTokenRecord.objects.get(jti=jti).used_at)
        deny.assert_not_called()


@skipUnless(connection.vendor == "postgresql", "requires real PostgreSQL row locks")
class ConcurrentRefreshRotationTests(TransactionTestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="concurrent-rotation")
        # Model a cold/unavailable denylist. Database single-use guarantees
        # must hold independently of Redis and across distinct connections.
        for name in ("is_jti_denied", "is_family_revoked"):
            patcher = patch(f"aegis_core.tokens.{name}", return_value=False)
            patcher.start()
            self.addCleanup(patcher.stop)
        for name in ("deny_jti", "deny_family"):
            patcher = patch(f"aegis_core.tokens.{name}")
            patcher.start()
            self.addCleanup(patcher.stop)

    def overlapping_rotations(self, tokens, family):
        application = f"aegis-rotation-test-{uuid.uuid4().hex}"

        def rotate(raw):
            close_old_connections()
            try:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT set_config('application_name', %s, false)", [application])
                    cursor.execute("SET statement_timeout = '10s'")
                try:
                    return ("issued", rotate_refresh_token(raw))
                except TokenTheftDetected:
                    return ("theft", None)
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=len(tokens)) as pool:
            with transaction.atomic():
                # Hold the records until both workers reach a database lock.
                # The old implementation reads used_at before waiting on its
                # UPDATE; a correct implementation locks before deciding.
                list(RefreshTokenRecord.objects.select_for_update().filter(family_id=family))
                futures = [pool.submit(rotate, raw) for raw in tokens]
                deadline = time.monotonic() + 5
                waiting = 0
                while time.monotonic() < deadline:
                    with connection.cursor() as cursor:
                        cursor.execute("SELECT pg_stat_clear_snapshot()")
                        cursor.execute(
                            "SELECT count(*) FROM pg_stat_activity "
                            "WHERE application_name = %s AND wait_event_type = 'Lock'",
                            [application],
                        )
                        waiting = cursor.fetchone()[0]
                    if waiting == len(tokens):
                        break
                    time.sleep(0.01)
                self.assertEqual(waiting, len(tokens), "workers did not overlap at the database")
            return [future.result(timeout=10) for future in futures]

    def test_concurrent_redemption_issues_only_one_successor_and_revokes_the_family(self):
        initial = issue_initial_pair(self.user)
        family = RefreshToken(initial.refresh)["family_id"]
        outcomes = self.overlapping_rotations([initial.refresh, initial.refresh], family)
        self.assertEqual([kind for kind, _ in outcomes].count("issued"), 1)
        self.assertEqual([kind for kind, _ in outcomes].count("theft"), 1)
        self.assertFalse(
            RefreshTokenRecord.objects.filter(family_id=family, revoked_at__isnull=True).exists()
        )

    def test_ancestor_replay_cannot_leave_a_concurrently_issued_descendant_active(self):
        initial = issue_initial_pair(self.user)
        current = rotate_refresh_token(initial.refresh)
        family = RefreshToken(initial.refresh)["family_id"]
        outcomes = self.overlapping_rotations([initial.refresh, current.refresh], family)
        self.assertIn("theft", [kind for kind, _ in outcomes])
        self.assertFalse(
            RefreshTokenRecord.objects.filter(family_id=family, revoked_at__isnull=True).exists()
        )
