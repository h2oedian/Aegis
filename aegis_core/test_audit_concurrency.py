import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from unittest import skipUnless
from unittest.mock import patch

from django.db import close_old_connections, connection, connections, transaction
from django.test import TransactionTestCase

from .audit import record_event, verify_chain
from .models import AuditLog


@skipUnless(connection.vendor == "postgresql", "requires real PostgreSQL row locks")
class ConcurrentAuditAppendTests(TransactionTestCase):
    def append_overlapping_events(self):
        application = f"aegis-audit-test-{uuid.uuid4().hex}"
        release = threading.Event()
        ready_lock = threading.Lock()
        ready = 0
        create = AuditLog.objects.create

        def paused_create(**kwargs):
            nonlocal ready
            with ready_lock:
                ready += 1
            if not release.wait(timeout=10):
                raise AssertionError("audit append was never released")
            return create(**kwargs)

        def append(index):
            close_old_connections()
            try:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT set_config('application_name', %s, false)", [application])
                    cursor.execute("SET statement_timeout = '10s'")
                return record_event("concurrent_event", {"worker": index}).pk
            finally:
                connections.close_all()

        with patch("aegis_core.audit.AuditLog.objects.create", side_effect=paused_create):
            with ThreadPoolExecutor(max_workers=2) as pool:
                try:
                    with transaction.atomic():
                        # If a tail exists, force both workers to wait before
                        # either can append. For an empty chain, pause insertion
                        # until the other worker reaches insertion or a DB lock.
                        AuditLog.objects.select_for_update().order_by("-id").first()
                        futures = [pool.submit(append, index) for index in range(2)]
                        deadline = time.monotonic() + 5
                        overlapping = 0
                        while time.monotonic() < deadline:
                            with connection.cursor() as cursor:
                                cursor.execute("SELECT pg_stat_clear_snapshot()")
                                cursor.execute(
                                    "SELECT count(*) FROM pg_stat_activity "
                                    "WHERE application_name = %s AND wait_event_type = 'Lock'",
                                    [application],
                                )
                                waiting = cursor.fetchone()[0]
                            with ready_lock:
                                overlapping = waiting + ready
                            if overlapping == 2:
                                break
                            time.sleep(0.01)
                        self.assertEqual(overlapping, 2, "audit writers did not overlap")
                finally:
                    release.set()
                return [future.result(timeout=10) for future in futures]

    def test_simultaneous_first_events_form_one_chain(self):
        self.assertEqual(len(set(self.append_overlapping_events())), 2)
        self.assertEqual(AuditLog.objects.count(), 2)
        self.assertTrue(verify_chain().valid)

    def test_waiting_appenders_reread_the_tail_after_serialization(self):
        record_event("seed")
        self.assertEqual(len(set(self.append_overlapping_events())), 2)
        self.assertEqual(AuditLog.objects.count(), 3)
        self.assertTrue(verify_chain().valid)
