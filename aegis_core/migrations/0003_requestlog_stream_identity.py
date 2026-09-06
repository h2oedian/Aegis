from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):
    dependencies = [("aegis_core", "0002_limit_user_agent_length")]

    operations = [
        migrations.AddField(
            model_name="requestlog",
            name="stream_id",
            field=models.CharField(
                editable=False, max_length=64, null=True, unique=True
            ),
        ),
        migrations.AlterField(
            model_name="requestlog",
            name="created_at",
            field=models.DateTimeField(
                db_index=True, default=django.utils.timezone.now
            ),
        ),
    ]
