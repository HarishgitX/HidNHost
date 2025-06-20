from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('register/', views.register, name='register'),
    path('user/login/', views.user_login, name='user_login'),
    path('admin/login/', views.admin_login, name='admin_login'),
    path('logout/', views.custom_logout, name='logout'),
    path('upload/', views.upload_file, name='upload_file'),
    path('download/<int:file_id>/', views.download_file, name='download_file'),
    path('admin/dashboard/', views.admin_dashboard, name='admin_dashboard'),
]
