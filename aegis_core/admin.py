from django.contrib import admin

from .models import RequestLog


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
    search_fields = ("path", "ip_address", "user_agent", "token_jti")
    readonly_fields = (
        "path",
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
