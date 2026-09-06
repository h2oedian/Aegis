from django.conf import settings
from django.db import models


class RequestLog(models.Model):
    path = models.CharField(max_length=2048, db_index=True)
    method = models.CharField(max_length=10, db_index=True)
    status_code = models.PositiveSmallIntegerField(db_index=True)
    duration_ms = models.FloatField()
    ip_address = models.GenericIPAddressField(null=True, blank=True, db_index=True)
    user_agent = models.CharField(max_length=1024, blank=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="aegis_request_logs",
    )
    token_jti = models.CharField(max_length=255, blank=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ("-created_at",)
        indexes = [
            models.Index(
                fields=("ip_address", "created_at"),
                name="aegis_core_ip_addr_6cc91e_idx",
            ),
            models.Index(
                fields=("status_code", "created_at"),
                name="aegis_core_status__9bc6ba_idx",
            ),
        ]

    def __str__(self):
        return f"{self.method} {self.path} -> {self.status_code}"
