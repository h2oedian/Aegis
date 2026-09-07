from django.urls import path

from .auth_views import LoginView, RefreshView
from .views import health

urlpatterns = [
    path("health/", health, name="health"),
    path("auth/login/", LoginView.as_view(), name="auth-login"),
    path("auth/refresh/", RefreshView.as_view(), name="auth-refresh"),
]

