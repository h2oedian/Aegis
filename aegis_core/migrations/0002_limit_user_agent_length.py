from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("aegis_core", "0001_initial")]

    operations = [
        migrations.AlterField(
            model_name="requestlog",
            name="user_agent",
            field=models.CharField(blank=True, max_length=1024),
        )
    ]
