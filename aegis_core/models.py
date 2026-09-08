from django.conf import settings
from django.db import models
from django.utils import timezone


class RequestLog(models.Model):
    stream_id = models.CharField(max_length=64, null=True, unique=True, editable=False)
    path = models.CharField(max_length=2048, db_index=True)
    query_string = models.CharField(max_length=2048, blank=True)
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
    created_at = models.DateTimeField(default=timezone.now, db_index=True)

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


class RefreshTokenRecord(models.Model):
    """One issued refresh token. Single-use: ``used_at`` is set the moment
    it's redeemed for a new pair, so redeeming it a second time means it
    was stolen. ``family_id`` links every token descended from one login,
    so a detected theft can revoke the whole chain at once."""

    jti = models.CharField(max_length=255, unique=True, db_index=True)
    family_id = models.CharField(max_length=64, db_index=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="aegis_refresh_tokens",
    )
    fingerprint = models.CharField(max_length=64, blank=True)
    issued_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=("family_id", "revoked_at"), name="aegis_core_family_rvkd_idx"),
        ]

    def __str__(self):
        return f"{self.user_id}:{self.family_id}:{self.jti[:8]}"


class AuditLogLock(models.Model):
    """Internal singleton that serializes appends, even for an empty log."""

    id = models.PositiveSmallIntegerField(primary_key=True, default=1, editable=False)

    class Meta:
        constraints = [
            models.CheckConstraint(condition=models.Q(id=1), name="aegis_audit_single_lock"),
        ]


class AuditLog(models.Model):
    """A tamper-evident record of security-significant events (token theft,
    an attack blocked, ...). Each row embeds the previous row's ``hash`` in
    its own ``previous_hash`` before hashing itself, so altering or deleting
    any past row breaks every hash after it -- verify_audit_log detects
    exactly where. Rows are written by aegis_core.audit.record_event, never
    edited afterwards."""

    event_type = models.CharField(max_length=100, db_index=True)
    payload = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(default=timezone.now, db_index=True)
    previous_hash = models.CharField(max_length=64)
    hash = models.CharField(max_length=64, unique=True, db_index=True)

    class Meta:
        ordering = ("id",)

    def __str__(self):
        return f"{self.created_at:%Y-%m-%d %H:%M:%S} {self.event_type}"
