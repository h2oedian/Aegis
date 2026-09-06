# Generated manually for the initial Aegis telemetry schema.
import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = [migrations.swappable_dependency(settings.AUTH_USER_MODEL)]

    operations = [
        migrations.CreateModel(
            name="RequestLog",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("path", models.CharField(db_index=True, max_length=2048)),
                ("method", models.CharField(db_index=True, max_length=10)),
                ("status_code", models.PositiveSmallIntegerField(db_index=True)),
                ("duration_ms", models.FloatField()),
                ("ip_address", models.GenericIPAddressField(blank=True, db_index=True, null=True)),
                ("user_agent", models.TextField(blank=True)),
                ("token_jti", models.CharField(blank=True, db_index=True, max_length=255)),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                ("user", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="aegis_request_logs", to=settings.AUTH_USER_MODEL)),
            ],
            options={"ordering": ("-created_at",)},
        ),
        migrations.AddIndex(
            model_name="requestlog",
            index=models.Index(fields=["ip_address", "created_at"], name="aegis_core_ip_addr_6cc91e_idx"),
        ),
        migrations.AddIndex(
            model_name="requestlog",
            index=models.Index(fields=["status_code", "created_at"], name="aegis_core_status__9bc6ba_idx"),
        ),
    ]
