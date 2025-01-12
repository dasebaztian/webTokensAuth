from django.shortcuts import redirect
from django.utils import timezone
from datetime import timedelta
from . import llavesElipticas as key
from database.models import Usuario

def login_y_verificar_llaves(vista):
    def interna(request, *args, **kargs):
        if not request.session.get('logueado', False):
            return redirect('/login')
        usuario = request.session.get('usuario', None)
        if usuario:
            try:
                usuario_bd = Usuario.objects.get(usuario=usuario)
                hora_actual = timezone.localtime(timezone.now())
                hora_expiracion_local = timezone.localtime(usuario_bd.date_expire_key)
                
                # Si la llave ha expirado, regenerarla
                if hora_expiracion_local <= hora_actual:
                    llavePrivada = key.generar_llave_privada()
                    llavePublica = key.generar_llave_publica(llavePrivada)

                    llaveprivada_pem = key.convertir_llave_privada_bytes(llavePrivada)
                    llavepublica_pem = key.convertir_llave_publica_bytes(llavePublica)

                    llave_aes = key.generar_llave_aes_from_password(usuario_bd.passwd)
                    iv = key.os.urandom(16)
                    llavePrivada_cifrada = key.cifrar(llaveprivada_pem, llave_aes, iv)

                    # Actualizar los campos en la base de datos
                    usuario_bd.privkey = llavePrivada_cifrada
                    usuario_bd.pubkey = llavepublica_pem.decode('utf-8')
                    usuario_bd.iv = iv
                    usuario_bd.date_expire_key = timezone.localtime(timezone.now() + timedelta(minutes=5))
                    usuario_bd.save()
            except Usuario.DoesNotExist:
                # Si el usuario no existe, redirigir al login
                return redirect('/login')
        return vista(request, *args, **kargs)
    return interna
    
