
from django.http import HttpResponse, JsonResponse
from django.template import Template, Context
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render, redirect

from Final import decoradores
from . import llavesElipticas as key
from . import hasher as hash
from database.models import Usuario



def campo_vacio(campo):
    return campo.strip() == ''

def inicio(request):
    t = "base.html"
    if request.method == 'GET':
        return render(request,t)
    elif request.method == 'POST':
        errores = []
        usuario = request.POST.get('usuario', '')
        passwd = request.POST.get('passwd', '')
        if campo_vacio(usuario):
            errores.append("El usuario no puede estar vacío")
        if campo_vacio(passwd):
            errores.append("La contraseña no puede estar vacía")
        if errores:
            return render(request, t, {'errores': errores})
        else:
            pass
        ##Crear la sesión 
            
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
    if request.method == 'GET':
        return render(request, 'login.html')
    elif request.method == 'POST':
        usuario = request.POST.get('usuario','')
        password = request.POST.get('passwd','')
        
        if not usuario or not password:
            errores = [] #Arreglo de errores
            errores.append('El usuario o contraseña no pueden estar vacíos')
            return render(request, 'login.html', {'errores': errores})
        try:
            usuario_bd = Usuario.objects.get(usuario=usuario)
            salt_bd = usuario_bd.salt_passwd
            passwd_bd = usuario_bd.passwd

            if hash.verificarPassword(password,passwd_bd, salt_bd):
                request.session['logueado'] = True
                return redirect('/firmar')
            else:
                errores = []
                errores.append("Usuario y/o Contraseña incorrectos")
                return render(request, 'login.html', {'errores': errores})
        except:
            errores = []
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
def verificar(request):
    t = "request.html"
    return render(request,t)

