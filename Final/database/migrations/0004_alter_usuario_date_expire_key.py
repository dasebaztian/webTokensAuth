# Generated by Django 5.1.4 on 2025-01-12 03:55

import database.models
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('database', '0003_usuario_date_expire_key'),
    ]

    operations = [
        migrations.AlterField(
            model_name='usuario',
            name='date_expire_key',
            field=models.DateTimeField(default=database.models.default_expiration),
        ),
    ]