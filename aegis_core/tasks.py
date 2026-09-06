import socket
from datetime import datetime, timezone

from celery import shared_task
from django.conf import settings
from django.contrib.auth import get_user_model
from redis.exceptions import RedisError, ResponseError

from .models import RequestLog
from .redis_client import get_redis_client


def _ensure_consumer_group(redis_client):
    try:
        redis_client.xgroup_create(
            settings.AEGIS_REQUEST_STREAM,
            settings.AEGIS_REQUEST_CONSUMER_GROUP,
            id="0",
            mkstream=True,
        )
    except ResponseError as exc:
        if "BUSYGROUP" not in str(exc):
            raise


def _to_request_logs(messages):
    user_ids = {fields.get("user_id") for _, fields in messages if fields.get("user_id")}
    valid_user_ids = set(
        get_user_model().objects.filter(pk__in=user_ids).values_list("pk", flat=True)
    )

    logs = []
    for stream_id, fields in messages:
        raw_user_id = fields.get("user_id")
        try:
            user_id = int(raw_user_id) if raw_user_id else None
        except (TypeError, ValueError):
            user_id = None
        if user_id not in valid_user_ids:
            user_id = None

        occurred_at_ms = int(fields["occurred_at_ms"])
        logs.append(
            RequestLog(
                stream_id=stream_id,
                path=fields.get("path", "")[:2048],
                method=fields.get("method", "")[:10],
                status_code=int(fields.get("status_code", 0)),
                duration_ms=float(fields.get("duration_ms", 0)),
                ip_address=fields.get("ip_address") or None,
                user_agent=fields.get("user_agent", "")[:1024],
                user_id=user_id,
                token_jti=fields.get("token_jti", "")[:255],
                created_at=datetime.fromtimestamp(occurred_at_ms / 1000, tz=timezone.utc),
            )
        )
    return logs


@shared_task(
    autoretry_for=(RedisError,),
    retry_backoff=True,
    retry_kwargs={"max_retries": 3},
)
def consume_request_stream():
    redis_client = get_redis_client()
    _ensure_consumer_group(redis_client)
    consumer_name = f"{socket.gethostname()}-{consume_request_stream.request.id or 'periodic'}"
    _, messages, _ = redis_client.xautoclaim(
        settings.AEGIS_REQUEST_STREAM,
        settings.AEGIS_REQUEST_CONSUMER_GROUP,
        consumer_name,
        min_idle_time=settings.AEGIS_REQUEST_CLAIM_IDLE_MS,
        start_id="0-0",
        count=settings.AEGIS_REQUEST_BATCH_SIZE,
    )
    if not messages:
        streams = redis_client.xreadgroup(
            settings.AEGIS_REQUEST_CONSUMER_GROUP,
            consumer_name,
            {settings.AEGIS_REQUEST_STREAM: ">"},
            count=settings.AEGIS_REQUEST_BATCH_SIZE,
            block=1,
        )
        messages = [
            message for _, stream_messages in streams for message in stream_messages
        ]
    if not messages:
        return 0

    RequestLog.objects.bulk_create(_to_request_logs(messages), ignore_conflicts=True)
    redis_client.xack(
        settings.AEGIS_REQUEST_STREAM,
        settings.AEGIS_REQUEST_CONSUMER_GROUP,
        *(stream_id for stream_id, _ in messages),
    )
    return len(messages)
