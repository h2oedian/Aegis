from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.authentication import JWTAuthentication

from .token_denylist import is_family_revoked, is_jti_denied


class FamilyAwareJWTAuthentication(JWTAuthentication):
    """JWTAuthentication, plus instant rejection of a revoked token.

    A stolen refresh token gets its own jti (and the whole family it
    belongs to) denylisted the moment reuse is detected. Checking that here
    means an access token already issued from a compromised family stops
    working immediately, instead of quietly remaining valid until its own
    short expiry passes.
    """

    def get_user(self, validated_token):
        jti = str(validated_token.get("jti", ""))
        family_id = validated_token.get("family_id")

        if jti and is_jti_denied(jti):
            raise AuthenticationFailed("Token has been revoked.")
        if family_id and is_family_revoked(family_id):
            raise AuthenticationFailed("Token's session has been revoked.")

        return super().get_user(validated_token)
