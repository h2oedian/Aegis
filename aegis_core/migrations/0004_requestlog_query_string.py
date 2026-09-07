from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("aegis_core", "0003_requestlog_stream_identity")]

    operations = [
        migrations.AddField(
            model_name="requestlog",
            name="query_string",
            field=models.CharField(blank=True, default="", max_length=2048),
            preserve_default=False,
        ),
    ]
