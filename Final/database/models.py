from django.db import models
from datetime import timedelta
from django.utils import timezone


def default_expiration():
    return timezone.localtime(timezone.now()) + timedelta(minutes=10)
# Create your models here.
class Usuario(models.Model):
    usuario = models.CharField(max_length=20, unique=True)
    nombre = models.CharField(max_length=50)
    correo = models.CharField(max_length=100)
    
    salt_passwd = models.BinaryField(default=b'')
    passwd = models.CharField(max_length=129)
    pubkey = models.CharField(max_length=215)
    privkey = models.BinaryField(default=b'')
    iv = models.BinaryField(default=b'')

    #Campo para validar el tiempo de expiración
    date_expire_key = models.DateTimeField(default=default_expiration)