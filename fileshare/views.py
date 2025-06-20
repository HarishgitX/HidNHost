from django.core.exceptions import ObjectDoesNotExist
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, HttpResponseForbidden
from .forms import CustomUserCreationForm, UploadFileForm, UserLoginForm
from .models import UploadedFile, FileEncryptionInfo, CustomUser
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os
from django.conf import settings


def home(request):
    return render(request, 'fileshare/home.html')

def register(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            return redirect('home')
    else:
        form = CustomUserCreationForm()
    return render(request, 'fileshare/register.html', {'form': form})

def user_login(request):
    if request.method == 'POST':
        form = UserLoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                if user.role == 'admin':
                    return redirect('admin_dashboard')
                else:
                    return redirect('upload_file')
            else:
                form.add_error(None, "Invalid credentials.")
    else:
        form = UserLoginForm()
    return render(request, 'fileshare/user_login.html', {'form': form})

def admin_login(request):
    if request.method == 'POST':
        form = UserLoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            user = authenticate(request, username=username, password=password)
            if user is not None and user.role == 'admin':
                login(request, user)
                return redirect('admin_dashboard')
            else:
                form.add_error(None, "Invalid credentials or not an admin.")
    else:
        form = UserLoginForm()
    return render(request, 'fileshare/admin_login.html', {'form': form})

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, HttpResponseForbidden, FileResponse
from django.core.exceptions import ObjectDoesNotExist
from .forms import UploadFileForm
from .models import UploadedFile, FileEncryptionInfo
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os

@login_required
def upload_file(request):
    if request.method == 'POST':
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_file = request.FILES['file']
            original_filename = uploaded_file.name

            # Read raw bytes from the uploaded file
            file_data = uploaded_file.read()

            # Encrypt using AES EAX
            key = get_random_bytes(16)
            cipher = AES.new(key, AES.MODE_EAX)
            ciphertext, tag = cipher.encrypt_and_digest(file_data)

            # Create encrypted file path
            encrypted_filename = f'encrypted_{original_filename}'
            encrypted_path = os.path.join(settings.MEDIA_ROOT, 'uploads', encrypted_filename)
            os.makedirs(os.path.dirname(encrypted_path), exist_ok=True)

            # Save encrypted content to disk (raw bytes)
            with open(encrypted_path, 'wb') as f:
                f.write(cipher.nonce)
                f.write(tag)
                f.write(ciphertext)

            # Save model reference (relative path)
            file_model = UploadedFile.objects.create(
                user=request.user,
                file=f'uploads/{encrypted_filename}',
                encrypted=True
            )

            FileEncryptionInfo.objects.create(
                file=file_model,
                key=key,
                nonce=cipher.nonce,
                tag=tag
            )

            return redirect('upload_file')
    else:
        form = UploadFileForm()

    files = UploadedFile.objects.filter(user=request.user)
    return render(request, 'fileshare/upload_file.html', {'form': form, 'files': files})


@login_required
def download_file(request, file_id):
    file_obj = get_object_or_404(UploadedFile, pk=file_id)
    if file_obj.user != request.user:
        return HttpResponseForbidden("You do not have permission to access this file.")

    file_path = os.path.join('media', file_obj.file.name)

    if file_obj.encrypted:
        try:
            enc_info = FileEncryptionInfo.objects.get(file=file_obj)
        except ObjectDoesNotExist:
            return HttpResponseForbidden("Encryption info missing for this file.")

        try:
            with open(file_path, 'rb') as f:
                nonce = f.read(16)
                tag = f.read(16)
                ciphertext = f.read()

            cipher = AES.new(enc_info.key, AES.MODE_EAX, nonce=nonce)
            data = cipher.decrypt_and_verify(ciphertext, tag)

            original_filename = os.path.basename(file_obj.file.name)
            if original_filename.startswith('encrypted_'):
                original_filename = original_filename[len('encrypted_'):]

            response = HttpResponse(data, content_type='application/octet-stream')
            response['Content-Disposition'] = f'attachment; filename="{original_filename}"'
            return response

        except Exception as e:
            print("Decryption error:", str(e))
            return HttpResponseForbidden("Failed to decrypt file. It may be corrupted.")
    else:
        return FileResponse(file_obj.file, as_attachment=True)


@login_required
def admin_dashboard(request):
    if request.user.role != 'admin':
        return HttpResponseForbidden("You must be an admin to access this page.")
    users = CustomUser.objects.all()
    return render(request, 'fileshare/admin_dashboard.html', {'users': users})

@login_required
def custom_logout(request):
    logout(request)
    return redirect('home')
