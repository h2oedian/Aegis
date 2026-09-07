import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("aegis_core", "0006_refreshtokenrecord_fingerprint")]

    operations = [
        migrations.CreateModel(
            name="AuditLog",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True, primary_key=True, serialize=False, verbose_name="ID"
                    ),
                ),
                ("event_type", models.CharField(db_index=True, max_length=100)),
                ("payload", models.JSONField(blank=True, default=dict)),
                ("created_at", models.DateTimeField(db_index=True, default=django.utils.timezone.now)),
                ("previous_hash", models.CharField(max_length=64)),
                ("hash", models.CharField(db_index=True, max_length=64, unique=True)),
            ],
            options={"ordering": ("id",)},
        ),
    ]
