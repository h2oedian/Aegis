from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("aegis_core", "0007_auditlog"),
    ]

    operations = [
        migrations.CreateModel(
            name="AuditLogLock",
            fields=[
                (
                    "id",
                    models.PositiveSmallIntegerField(
                        default=1, editable=False, primary_key=True, serialize=False
                    ),
                ),
            ],
            options={
                "constraints": [
                    models.CheckConstraint(
                        condition=models.Q(id=1), name="aegis_audit_single_lock"
                    ),
                ],
            },
        ),
    ]
