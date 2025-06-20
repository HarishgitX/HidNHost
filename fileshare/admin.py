from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser, UploadedFile

class CustomUserAdmin(UserAdmin):
    list_display = ('username', 'email', 'role', 'file_count')

    def file_count(self, obj):
        return UploadedFile.objects.filter(user=obj).count()
    file_count.short_description = 'Number of Uploaded Files'

admin.site.register(CustomUser, CustomUserAdmin)
admin.site.register(UploadedFile)

