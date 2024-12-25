
from django.http import HttpResponse, JsonResponse
from django.template import Template, Context
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render, redirect


def inicio(request):
    t = "base.html"
    return render(request,t)

def registro(request):
    t = "registro.html"
    if request.method == 'GET':
        return render(request, t)
    elif request.method == 'POST':
       ## Validaciones
        return redirect('/login')

def login(request):
    t = "login.html"
    return render(request,t)

def generar(request):
    t = "generar.html"
    return render(request,t)

def firmar(request):
    t = "firmar.html"
    return render(request,t)

def verificar(request):
    t = "request.html"
    return render(request,t)
