from django.db import models

# Create your models here.
class Usuario(models.Model):
    usuario = models.CharField(max_length=20, unique=True)
    nombre = models.CharField(max_length=50)
    correo = models.CharField(max_length=100)
    passwd = models.CharField(max_length=129)
    pubkey = models.CharField(max_length=100)
    privkey = models.CharField(max_length=100)
