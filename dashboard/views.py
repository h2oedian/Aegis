from django.contrib.admin.views.decorators import staff_member_required
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.urls import reverse
from django.views.decorators.http import require_POST

from aegis_core.audit import record_event
from aegis_ml.decision import DecisionEngine

from .metrics import build_snapshot


@staff_member_required
def index(request):
    return render(request, "dashboard/index.html", {"snapshot": build_snapshot()})


@staff_member_required
def volume_partial(request):
    return render(request, "dashboard/_volume_chart.html", {"snapshot": build_snapshot()})


@staff_member_required
def risky_ips_partial(request):
    return render(request, "dashboard/_risky_ips.html", {"snapshot": build_snapshot()})


@staff_member_required
def events_partial(request):
    return render(request, "dashboard/_events.html", {"snapshot": build_snapshot()})


@staff_member_required
@require_POST
def ban_ip(request):
    ip_address = request.POST.get("ip_address", "").strip()
    if ip_address:
        DecisionEngine().ban(ip_address)
        record_event("manual_ban", {"ip_address": ip_address, "staff_user": request.user.username})
    return HttpResponseRedirect(reverse("dashboard:index"))


@staff_member_required
@require_POST
def unban_ip(request):
    ip_address = request.POST.get("ip_address", "").strip()
    if ip_address:
        DecisionEngine().unban(ip_address)
        record_event("manual_unban", {"ip_address": ip_address, "staff_user": request.user.username})
    return HttpResponseRedirect(reverse("dashboard:index"))
