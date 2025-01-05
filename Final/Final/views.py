from asyncio import sleep
from django.http import HttpResponse, JsonResponse
from django.template import Template, Context
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render, redirect

import re
from Final import decoradores
from . import llavesElipticas as key
from . import hasher as hash
from . import firmas as firm
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
        request.session['logueado'] = False
        request.session['usuario'] = ''
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
        request.session['logueado'] = False
        request.session['usuario'] = ''
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
    if request.method == 'POST':
        usuario = request.session.get('usuario')
        passwd = request.POST.get('passwd')
        archivo = request.FILES.get('archivo')

        if not usuario or not archivo:
            return render(request, t, {'errores': ['Faltan datos requeridos']})

        try:
            usuario_bd = Usuario.objects.get(usuario=usuario)
            privkey_cifrada = usuario_bd.privkey
            pubkey = usuario_bd.pubkey
            salt_bd = usuario_bd.salt_passwd
            passwd_bd = usuario_bd.passwd

            if hash.verificarPassword(passwd, passwd_bd, salt_bd):
                llavePrivada_pem = key.descifrar(
                    privkey_cifrada,
                    key.generar_llave_aes_from_password(passwd_bd),
                    usuario_bd.iv
                )
                privkey_tipo_llave = key.convertir_bytes_llave_privada(llavePrivada_pem)

                # Leer el archivo subido
                archivo_bytes = archivo.read()

                # Firmar el archivo
                firma = firm.firmado(privkey_tipo_llave, archivo_bytes)

                # Preparar respuesta para descarga
                response = HttpResponse(firma, content_type='application/octet-stream')
                response['Content-Disposition'] = f'attachment; filename={archivo.name}_sign.sig'
                return response
            else:
                return render(request, t, {'errores': ['Contraseña incorrecta']})

        except Usuario.DoesNotExist:
            return render(request, 'login.html', {'errores': ['Usuario no encontrado']})
        except Exception as e:
            return render(request, t, {'errores': [f'Error inesperado: {str(e)}']})
    else:
        return render(request, t)

@decoradores.login_requerido
def verificar(request):
    t = "verificar.html"
    if request.method == 'POST':
        archivo = request.FILES['archivo']
        signature = request.FILES['firma']
        usuario = request.POST.get('usuario', '')
        
        archivo_binario = archivo.read()
        signature_binario = signature.read()
        if Usuario.objects.get(usuario=usuario):
            usuario_bd = Usuario.objects.get(usuario=usuario)
            llavePublica_pem = usuario_bd.pubkey.encode('utf-8')
            llavePublica = key.convertir_bytes_llave_publica(llavePublica_pem)

            if firm.verificacion(llavePublica, signature_binario, archivo_binario):
                return render(request, t, {'success': ['Las firmas coinciden, archivo verificado']})
            else:
                return render(request, t, {'errores': ['Las firmas no coinciden']})
        else:
            return render(request, t, {'errores': ['No existe ese usuario']})
    else:
        return render(request,t)

