from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.forms import AuthenticationForm
from django.contrib import messages
from django.core.cache import cache
from django.utils import timezone
import datetime
from django.contrib.auth.decorators import login_required
import random

def gerador_de_senhas():
    caracteres = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
    senha = ""

    for i in range(10):
        senha += caracteres[random.randint(0, len(caracteres) - 1)]
    return senha

def register_view(request):
    if request.method == "POST":
        username = request.POST.get("username")
        email = request.POST.get("email")
        password = request.POST.get("password")
        password2 = request.POST.get("password2")

        if password != password2:
            messages.error(request, "As senhas não coincidem.")
            return redirect('register')

        if User.objects.filter(username=username).exists():
            messages.error(request, "Nome de usuário já está em uso.")
            return redirect('register')

        if User.objects.filter(email=email).exists():
            messages.error(request, "Este e-mail já está cadastrado.")
            return redirect('register')

        user = User.objects.create_user(username=username, email=email, password=password)
        user.save()

        usuario_autenticado = authenticate(request, username=username, password=password)
        if usuario_autenticado:
            login(request, usuario_autenticado)
            messages.success(request, "Registro concluído com sucesso!")
            return redirect('login')

    return render(request, 'register.html')


def login_view(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        if username:
            failed_attempts_key = f'failed_login_{username}'
            lockout_time_key = f'lockout_time_{username}'

            failed_attempts = cache.get(failed_attempts_key, 0)
            lockout_time = cache.get(lockout_time_key)

            if lockout_time and timezone.now() < lockout_time:
                time_remaining = lockout_time - timezone.now()
                error_message = f"Conta bloqueada. Tente novamente em {int(time_remaining.total_seconds())} segundos."
                form_login = AuthenticationForm()
                return render(request, 'login.html', {
                    'form_login': form_login,
                    'error_message': error_message,
                })

            usuario = authenticate(request, username=username, password=password)

            if usuario is not None:
                login(request, usuario)
                cache.delete(failed_attempts_key) 
                cache.delete(lockout_time_key)
                return redirect('profile')
            else:
                failed_attempts += 1
                cache.set(failed_attempts_key, failed_attempts, 60 * 60 * 24)

                if failed_attempts >= 5:
                    lockout_duration = datetime.timedelta(minutes=1)
                    cache.set(lockout_time_key, timezone.now() + lockout_duration, lockout_duration.total_seconds())
                    error_message = "Conta bloqueada por 1 minuto devido a muitas tentativas de login incorretas."
                else:
                    error_message = "Credenciais inválidas. Tente novamente."

                form_login = AuthenticationForm()
                return render(request, 'login.html', {
                    'form_login': form_login,
                    'error_message': error_message,
                })
        else:
            form_login = AuthenticationForm()
            return render(request, 'login.html', {'form_login': form_login})
    else:
        form_login = AuthenticationForm()
    return render(request, 'login.html', {'form_login': form_login})


def logout_view(request):
    logout(request)
    return redirect('login')

@login_required(login_url='login_view')
def profile_view(request):
    return render(request, 'profile.html')