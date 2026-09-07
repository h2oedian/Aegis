from django.conf import settings


def client_ip(request) -> str | None:
    """The request's client IP, honoring X-Forwarded-For only when configured
    to trust it (i.e. behind a correctly configured proxy)."""
    if settings.AEGIS_TRUST_PROXY_HEADERS:
        forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR", "")
        if forwarded_for:
            return forwarded_for.split(",", maxsplit=1)[0].strip() or None
    return request.META.get("REMOTE_ADDR") or None
