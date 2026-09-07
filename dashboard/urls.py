from django.urls import path

from . import views

app_name = "dashboard"

urlpatterns = [
    path("", views.index, name="index"),
    path("partials/volume/", views.volume_partial, name="volume-partial"),
    path("partials/risky-ips/", views.risky_ips_partial, name="risky-ips-partial"),
    path("partials/events/", views.events_partial, name="events-partial"),
    path("ban/", views.ban_ip, name="ban"),
    path("unban/", views.unban_ip, name="unban"),
]
