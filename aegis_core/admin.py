from django.contrib import admin

from .models import AuditLog, RefreshTokenRecord, RequestLog


@admin.register(RequestLog)
class RequestLogAdmin(admin.ModelAdmin):
    list_display = (
        "created_at",
        "method",
        "path",
        "status_code",
        "duration_ms",
        "ip_address",
        "user",
    )
    list_filter = ("method", "status_code", "created_at")
    search_fields = ("path", "query_string", "ip_address", "user_agent", "token_jti")
    readonly_fields = (
        "path",
        "query_string",
        "method",
        "status_code",
        "duration_ms",
        "ip_address",
        "user_agent",
        "user",
        "token_jti",
        "created_at",
    )

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ("created_at", "event_type", "hash")
    list_filter = ("event_type", "created_at")
    search_fields = ("event_type", "hash", "previous_hash")
    readonly_fields = ("event_type", "payload", "created_at", "previous_hash", "hash")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        # Deleting a row (even the tail) is exactly the tampering this log
        # exists to detect -- verify_audit_log is how you'd notice it did.
        return False


@admin.register(RefreshTokenRecord)
class RefreshTokenRecordAdmin(admin.ModelAdmin):
    list_display = ("issued_at", "user", "family_id", "jti", "used_at", "revoked_at")
    list_filter = ("revoked_at", "issued_at")
    search_fields = ("family_id", "jti", "user__username")
    readonly_fields = (
        "jti",
        "family_id",
        "user",
        "issued_at",
        "expires_at",
        "used_at",
        "revoked_at",
    )

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False
