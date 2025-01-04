from django.http import HttpResponse, JsonResponse
from django.template import Template, Context
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render, redirect

import re
from Final import decoradores
from . import llavesElipticas as key
from . import hasher as hash
from database.models import Usuario


def campo_vacio(campo):
    return campo.strip() == ''

def validar_campo(campo):
    if re.match(r'^[a-zA-Z0-9 _-]+$', campo):
        return False
    else:
        return True
        
    
def registro(request):
    t = "registro.html"
    if request.method == 'GET':
        return render(request, t)
    elif request.method == 'POST':
        errores = [] #Arreglo de errores

        #Obtención de parámetros
        nombre = request.POST.get('nombre', '') 
        usuario = request.POST.get('usuario', '')
        email = request.POST.get('email', '')
        passwd = request.POST.get('passwd', '')
        passwd2 = request.POST.get('passwd2', '')
        
        #Verificación parámetros vacios
        if campo_vacio(nombre):
            errores.append("El nombre no puede estar vacío")
        if campo_vacio(usuario):
            errores.append("El usuario no puede estar vacío")
        if campo_vacio(email):
            errores.append("El email no puede estar vacío")
        if campo_vacio(passwd):
            errores.append("La contraseña no puede estar vacía")
        if campo_vacio(passwd2):
            errores.append("La confirmación de contraseña no puede estar vacía")

        ##Validación de carácteres especiales
        if validar_campo(nombre):
            errores.append("El nombre no puede contener carácteres especiales")
        if validar_campo(usuario):
            errores.append("El usuario no puede contener carácters especiales")
        if validar_campo(passwd):
            errores.append("La contraseña no puede contener carácteres especiales")
        if validar_campo(passwd2):
            errores.append("La confirmación de contraseña no puede contener carácteres espeiales")

        #verificación del contenido de parametros
        if not passwd==passwd2:
            errores.append("Las contraseñas no coinciden")
        if Usuario.objects.filter(usuario=usuario).exists():
            errores.append("El usuario ya esta ocupado")
        if Usuario.objects.filter(correo=email).exists():    
            errores.append("El correo ya está registrado")
            
        #Respuesta ante un error o más de los parámetros
        if errores:
            return render(request, t, {'errores': errores})
        else:
            ##Validar que el usuario no este registrado
            ##Guardar al usuario
            ##Crear las llaves y encriptarla con la contrseña

            salt_password_bd = key.os.urandom(16)##Guardarlo como binario en la base
            passwdHasheado =  hash.hashearPassword(passwd, salt_password_bd)##Guardarlo en la base como char

            llavePrivada = key.generar_llave_privada()
            llavePublica = key.generar_llave_publica(llavePrivada)

            llaveprivada_pem = key.convertir_llave_privada_bytes(llavePrivada)
            llavepublica_pem = key.convertir_llave_publica_bytes(llavePublica)##Guardar como char en la base .decode('utf-8')

            llave_aes = key.generar_llave_aes_from_password(passwdHasheado)            
            iv = key.os.urandom(16)##Guardar como binario en la base, debe cambiarse cuando se soliciten nuevas llaves
            llavePrivada_cifrada = key.cifrar(llaveprivada_pem, llave_aes, iv)##Guardar como binario en la base

            usuario_nuevo = Usuario(
                usuario=usuario,
                nombre=nombre,
                correo=email,
                salt_passwd=salt_password_bd,
                passwd=passwdHasheado,
                pubkey=llavepublica_pem.decode('utf-8'),
                privkey=llavePrivada_cifrada,
                iv=iv
            )
            usuario_nuevo.save()
            return redirect('/login')

def login(request):
    t = "login.html"
    errores = []
    if request.method == 'GET':
        return render(request, 'login.html')
    elif request.method == 'POST':
        usuario = request.POST.get('usuario','')
        passwd = request.POST.get('passwd','')

        if campo_vacio(usuario):
            errores.append("El usuario no puede estar vacío")
        if campo_vacio(passwd):
            errores.append("La contraseña no puede estar vacía")
        if not usuario or not passwd:
            errores.append('El usuario o contraseña no pueden estar vacíos')
        if errores:
            return render(request, 'login.html', {'errores': errores})
        else:
            try:
                usuario_bd = Usuario.objects.get(usuario=usuario)
                salt_bd = usuario_bd.salt_passwd
                passwd_bd = usuario_bd.passwd

                if hash.verificarPassword(passwd,passwd_bd, salt_bd):
                    request.session['logueado'] = True
                    request.session['usuario'] = usuario
                    return redirect('/firmar')
                else:
                    errores.append("Usuario y/o Contraseña incorrectos")
                    return render(request, 'login.html', {'errores': errores})
            except:
                errores.append('Usuario y/o Contraseña incorrectos')
                return render(request, 'login.html', {'errores': errores})
        

@decoradores.login_requerido
def generar(request):
    t = "generar.html"
    return render(request,t)

@decoradores.login_requerido
def firmar(request):
    t = "firmar.html"
    return render(request,t)

@decoradores.login_requerido
def priv(request):
    t = "firmar.html"
    return render(request,t)

@decoradores.login_requerido
def publ(request):
    if request.method == 'POST':
        usuario = request.session.get('usuario')  # Obtener el nombre de usuario desde la sesión
        try:
            # Buscar al usuario en la base de datos
            usuario_bd = Usuario.objects.get(usuario=usuario)
            pubkey = usuario_bd.pubkey

            # Crear una respuesta HTTP para la descarga de la llave privada
            response = HttpResponse(pubkey, content_type='application/octet-stream')
            response['Content-Disposition'] = f'attachment; filename={usuario}_public_key.pem'

            return response
        except Usuario.DoesNotExist:
            # Si no se encuentra el usuario
            return render(request, 'login.html')
    else:
        return render(request, 'login.html')

@decoradores.login_requerido
def verificar(request):
    t = "request.html"
    return render(request,t)

