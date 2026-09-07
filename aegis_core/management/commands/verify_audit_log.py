from django.core.management.base import BaseCommand

from aegis_core.audit import verify_chain
from aegis_core.models import AuditLog


class Command(BaseCommand):
    help = "Walk the AuditLog hash chain and report the exact record where it breaks, if any."

    def handle(self, *args, **options):
        result = verify_chain()

        if result.valid:
            self.stdout.write(
                self.style.SUCCESS(f"Chain intact: {result.checked} record(s) verified.")
            )
            return

        self.stdout.write(
            self.style.ERROR(
                f"Tampering detected at AuditLog id={result.broken_at_id} "
                f"(after {result.checked} clean record(s)): {result.reason}"
            )
        )
        try:
            record = AuditLog.objects.get(id=result.broken_at_id)
            self.stdout.write(f"  event_type: {record.event_type}")
            self.stdout.write(f"  created_at: {record.created_at.isoformat()}")
            self.stdout.write(f"  payload: {record.payload}")
        except AuditLog.DoesNotExist:
            self.stdout.write("  (record no longer exists -- it may have been deleted)")

        raise SystemExit(1)
