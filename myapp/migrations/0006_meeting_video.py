# Generated by Django 4.1.3 on 2023-01-08 06:52

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("myapp", "0005_meeting_is_cancelled_meeting_is_rejected"),
    ]

    operations = [
        migrations.AddField(
            model_name="meeting",
            name="video",
            field=models.FileField(blank=True, null=True, upload_to="videos/"),
        ),
    ]
