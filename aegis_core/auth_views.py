from django.contrib.auth import authenticate
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError

from .tokens import TokenTheftDetected, issue_initial_pair, rotate_refresh_token


class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        user = authenticate(
            request,
            username=request.data.get("username", ""),
            password=request.data.get("password", ""),
        )
        if user is None:
            return Response({"error": "invalid_credentials"}, status=401)

        pair = issue_initial_pair(user)
        return Response({"refresh": pair.refresh, "access": pair.access})


class RefreshView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        raw_refresh = request.data.get("refresh", "")
        if not raw_refresh:
            return Response({"error": "refresh_required"}, status=400)

        try:
            pair = rotate_refresh_token(raw_refresh)
        except TokenTheftDetected:
            return Response({"error": "token_reuse_detected"}, status=401)
        except TokenError:
            return Response({"error": "invalid_token"}, status=401)

        return Response({"refresh": pair.refresh, "access": pair.access})
