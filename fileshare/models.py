from django.contrib.auth.models import AbstractUser
from django.db import models
from django.conf import settings

class CustomUser(AbstractUser):
    ROLE_CHOICES = [
        ('user', 'User'),
        ('admin', 'Admin'),
    ]
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='user')

class UploadedFile(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    file = models.FileField(upload_to='uploads/')
    encrypted = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

class FileEncryptionInfo(models.Model):
    file = models.OneToOneField(UploadedFile, on_delete=models.CASCADE)
    key = models.BinaryField()
    nonce = models.BinaryField()
    tag = models.BinaryField()




