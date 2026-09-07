import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("aegis_core", "0004_requestlog_query_string"),
    ]

    operations = [
        migrations.CreateModel(
            name="RefreshTokenRecord",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True, primary_key=True, serialize=False, verbose_name="ID"
                    ),
                ),
                ("jti", models.CharField(db_index=True, max_length=255, unique=True)),
                ("family_id", models.CharField(db_index=True, max_length=64)),
                ("issued_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("expires_at", models.DateTimeField()),
                ("used_at", models.DateTimeField(blank=True, null=True)),
                ("revoked_at", models.DateTimeField(blank=True, null=True)),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="aegis_refresh_tokens",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
        ),
        migrations.AddIndex(
            model_name="refreshtokenrecord",
            index=models.Index(
                fields=["family_id", "revoked_at"], name="aegis_core_family_rvkd_idx"
            ),
        ),
    ]
