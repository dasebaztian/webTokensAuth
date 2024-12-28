
from django.http import HttpResponse, JsonResponse
from django.template import Template, Context
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render, redirect

from Final import decoradores
from database import models as Usuarios


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
        errores = []
        nombre = request.POST.get('nombre', '')
        usuario = request.POST.get('usuario', '')
        email = request.POST.get('email', '')
        passwd = request.POST.get('passwd', '')
        passwd2 = request.POST.get('passwd2', '')
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
        if errores:
            return render(request, t, {'errores': errores})
        else:
            ##Validar que el usuario no este registrado
            ##Guardar al usuario
            ##Crear las llaves y encriptarla con la contrseña
            return redirect('/login')

def login(request):
    t = "login.html"
    return render(request,t)

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
