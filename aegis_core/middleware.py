import logging
import time

from django.conf import settings
from django.db import DatabaseError

from .models import RequestLog

logger = logging.getLogger(__name__)


class RequestTelemetryMiddleware:
    """Persist non-sensitive request metadata for later security analysis."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        started_at = time.perf_counter()

        try:
            response = self.get_response(request)
        except Exception:
            self._store(request, 500, started_at)
            raise

        self._store(request, response.status_code, started_at)
        return response

    def _store(self, request, status_code, started_at):
        duration_ms = (time.perf_counter() - started_at) * 1000
        user = getattr(request, "user", None)
        authenticated_user = user if getattr(user, "is_authenticated", False) else None

        try:
            RequestLog.objects.create(
                path=request.path[:2048],
                method=request.method[:10],
                status_code=status_code,
                duration_ms=duration_ms,
                ip_address=self._client_ip(request),
                user_agent=request.META.get("HTTP_USER_AGENT", "")[:1024],
                user=authenticated_user,
                token_jti=self._token_jti(request),
            )
        except DatabaseError:
            # Telemetry must never make the protected API unavailable.
            logger.exception("Could not persist request telemetry")

    @staticmethod
    def _client_ip(request):
        if settings.AEGIS_TRUST_PROXY_HEADERS:
            forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR", "")
            if forwarded_for:
                return forwarded_for.split(",", maxsplit=1)[0].strip() or None
        return request.META.get("REMOTE_ADDR") or None

    @staticmethod
    def _token_jti(request):
        auth = getattr(request, "auth", None)
        payload = getattr(auth, "payload", None)
        if isinstance(payload, dict):
            return str(payload.get("jti", ""))[:255]
        return ""
