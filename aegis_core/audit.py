import hashlib
import json
from dataclasses import dataclass
from datetime import datetime

from django.db import transaction
from django.utils import timezone

from .models import AuditLog, AuditLogLock

GENESIS_HASH = "0" * 64


def _canonical_json(event_type: str, payload: dict, created_at: datetime, previous_hash: str) -> str:
    return json.dumps(
        {
            "event_type": event_type,
            "payload": payload,
            "created_at": created_at.isoformat(),
            "previous_hash": previous_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def compute_hash(event_type: str, payload: dict, created_at: datetime, previous_hash: str) -> str:
    canonical = _canonical_json(event_type, payload, created_at, previous_hash)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def record_event(event_type: str, payload: dict | None = None) -> AuditLog:
    """Append one tamper-evident row to the audit log.

    Lock a stable singleton before reading the tail. Locking the tail itself
    cannot protect an empty chain, and a waiting SELECT can retain an old
    tail from its statement snapshot even after another append commits.
    """
    payload = payload or {}
    with transaction.atomic():
        # The unique primary key also serializes concurrent first-use
        # creation. get_or_create retries the locked lookup after a conflict.
        AuditLogLock.objects.select_for_update().get_or_create(pk=1)
        tail = AuditLog.objects.order_by("-id").first()
        previous_hash = tail.hash if tail else GENESIS_HASH
        created_at = timezone.now()
        return AuditLog.objects.create(
            event_type=event_type,
            payload=payload,
            created_at=created_at,
            previous_hash=previous_hash,
            hash=compute_hash(event_type, payload, created_at, previous_hash),
        )


@dataclass(frozen=True)
class ChainVerification:
    valid: bool
    checked: int
    broken_at_id: int | None = None
    reason: str | None = None


def verify_chain() -> ChainVerification:
    """Walk the log in order, recomputing and re-linking every hash.

    Stops at the first row that doesn't fit -- either its previous_hash
    doesn't match the prior row's hash (a row was inserted, deleted, or
    reordered) or its stored hash doesn't match what its own content
    recomputes to (a row's content was altered in place) -- and reports
    that row's id as the exact point of tampering.
    """
    previous_hash = GENESIS_HASH
    checked = 0
    for record in AuditLog.objects.order_by("id").iterator():
        if record.previous_hash != previous_hash:
            return ChainVerification(
                valid=False,
                checked=checked,
                broken_at_id=record.id,
                reason="previous_hash does not match the prior record's hash",
            )
        expected_hash = compute_hash(
            record.event_type, record.payload, record.created_at, record.previous_hash
        )
        if expected_hash != record.hash:
            return ChainVerification(
                valid=False,
                checked=checked,
                broken_at_id=record.id,
                reason="stored hash does not match this record's recomputed content",
            )
        previous_hash = record.hash
        checked += 1
    return ChainVerification(valid=True, checked=checked)
