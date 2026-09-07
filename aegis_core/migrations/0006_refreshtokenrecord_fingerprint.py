from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("aegis_core", "0005_refreshtokenrecord")]

    operations = [
        migrations.AddField(
            model_name="refreshtokenrecord",
            name="fingerprint",
            field=models.CharField(blank=True, default="", max_length=64),
            preserve_default=False,
        ),
    ]
