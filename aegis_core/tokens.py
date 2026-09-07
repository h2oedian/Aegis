import uuid
from dataclasses import dataclass
from datetime import datetime, timezone as dt_timezone

from django.utils import timezone
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken

from .models import RefreshTokenRecord
from .token_denylist import deny_family, deny_jti, is_family_revoked, is_jti_denied


class TokenTheftDetected(Exception):
    """A refresh token was reused, missing, or its family already revoked."""


@dataclass(frozen=True)
class TokenPair:
    refresh: str
    access: str


def _record_for(
    refresh_token: RefreshToken, family_id: str, user, fingerprint: str | None
) -> RefreshTokenRecord:
    return RefreshTokenRecord.objects.create(
        jti=str(refresh_token["jti"]),
        family_id=family_id,
        user=user,
        fingerprint=fingerprint or "",
        expires_at=datetime.fromtimestamp(refresh_token["exp"], tz=dt_timezone.utc),
    )


def _issue_pair(user, family_id: str, fingerprint: str | None = None) -> TokenPair:
    refresh = RefreshToken.for_user(user)
    refresh["family_id"] = family_id
    if fingerprint:
        refresh["fingerprint"] = fingerprint
    _record_for(refresh, family_id, user, fingerprint)
    access = refresh.access_token
    return TokenPair(refresh=str(refresh), access=str(access))


def issue_initial_pair(user, *, fingerprint: str | None = None) -> TokenPair:
    """Start a brand new token family, e.g. on login. ``fingerprint`` (see
    aegis_core.fingerprint) binds every token in the family to this device
    for the rest of its life -- rotation carries it forward unchanged."""
    return _issue_pair(user, family_id=str(uuid.uuid4()), fingerprint=fingerprint)


def rotate_refresh_token(raw_refresh_token: str) -> TokenPair:
    """Redeem a refresh token for a new pair, detecting reuse as theft.

    Every refresh token is single-use. Rotation alone stops a silent
    eavesdropper from minting fresh tokens forever; reuse detection is what
    catches an attacker racing the legitimate client with a copy of a token
    that's already been redeemed -- whoever presents it second loses, and
    the whole family is revoked so neither party can continue.

    Raises rest_framework_simplejwt.exceptions.TokenError for a token that
    fails signature/expiry/type verification, and TokenTheftDetected for a
    token that verifies fine but has already been used or revoked.
    """
    old_token = RefreshToken(raw_refresh_token)
    jti = str(old_token["jti"])
    family_id = old_token.payload.get("family_id")
    if not family_id:
        raise TokenTheftDetected("Refresh token is missing its family claim")

    if is_jti_denied(jti) or is_family_revoked(family_id):
        _revoke_family(family_id)
        raise TokenTheftDetected(f"Refresh token reuse detected for family {family_id}")

    try:
        record = RefreshTokenRecord.objects.get(jti=jti)
    except RefreshTokenRecord.DoesNotExist:
        # Signed correctly but unknown to us -- treat it the same as theft.
        _revoke_family(family_id)
        raise TokenTheftDetected(f"Unknown refresh token for family {family_id}")

    if record.used_at is not None or record.revoked_at is not None:
        _revoke_family(family_id)
        raise TokenTheftDetected(f"Refresh token reuse detected for family {family_id}")

    record.used_at = timezone.now()
    record.save(update_fields=["used_at"])
    deny_jti(jti)

    return _issue_pair(record.user, family_id, fingerprint=record.fingerprint)


def _revoke_family(family_id: str) -> None:
    RefreshTokenRecord.objects.filter(family_id=family_id, revoked_at__isnull=True).update(
        revoked_at=timezone.now()
    )
    deny_family(family_id)


@dataclass(frozen=True)
class PeekedClaims:
    user_id: int | None
    fingerprint: str | None


def peek_access_token(auth_header: str) -> PeekedClaims | None:
    """Best-effort, unauthenticated peek at an Authorization header's JWT
    claims -- used only to enrich risk scoring (the impossible-travel and
    device-fingerprint rules need an identity/claim, not just an IP), never
    to grant access. A missing, malformed, expired, or revoked token just
    means no identity signal is available; enforcement stays entirely with
    FamilyAwareJWTAuthentication in the actual view.
    """
    prefix = "Bearer "
    if not auth_header.startswith(prefix):
        return None
    try:
        token = AccessToken(auth_header[len(prefix) :])
    except TokenError:
        return None
    return PeekedClaims(
        user_id=token.payload.get(api_settings.USER_ID_CLAIM),
        fingerprint=token.payload.get("fingerprint"),
    )
