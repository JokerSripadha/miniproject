# Generated by Django 5.0.7 on 2024-08-02 05:41

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Url',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('Url', models.CharField(max_length=200)),
                ('SubD', models.TextField(max_length=10000)),
                ('IPa', models.GenericIPAddressField()),
                ('Region', models.CharField(max_length=200)),
                ('Results', models.CharField(max_length=200)),
            ],
        ),
    ]
