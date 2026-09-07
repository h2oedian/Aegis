import logging
import time

from django.conf import settings
from redis.exceptions import RedisError

from .redis_client import get_redis_client
from .request_meta import client_ip

logger = logging.getLogger(__name__)


class RequestTelemetryMiddleware:
    """Publish non-sensitive request metadata without blocking the API."""

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
        user_id = str(user.pk) if getattr(user, "is_authenticated", False) else ""

        try:
            get_redis_client().xadd(
                settings.AEGIS_REQUEST_STREAM,
                {
                    "occurred_at_ms": str(time.time_ns() // 1_000_000),
                    "path": request.path[:2048],
                    "query_string": request.META.get("QUERY_STRING", "")[:2048],
                    "method": request.method[:10],
                    "status_code": str(status_code),
                    "duration_ms": f"{duration_ms:.6f}",
                    "ip_address": client_ip(request) or "",
                    "user_agent": request.META.get("HTTP_USER_AGENT", "")[:1024],
                    "user_id": user_id,
                    "token_jti": self._token_jti(request),
                },
                maxlen=settings.AEGIS_REQUEST_STREAM_MAX_LENGTH,
                approximate=True,
            )
        except RedisError as exc:
            # Security telemetry is fail-open: an unavailable Redis must not
            # make the protected API unavailable.
            logger.warning("Could not publish request telemetry: %s", exc)

    @staticmethod
    def _token_jti(request):
        auth = getattr(request, "auth", None)
        payload = getattr(auth, "payload", None)
        if isinstance(payload, dict):
            return str(payload.get("jti", ""))[:255]
        return ""
