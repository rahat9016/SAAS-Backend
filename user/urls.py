from django.urls import path
from .views import RegisterView, LoginView

urlpatterns = [
    path('auth/login/', LoginView.as_view(), name='Login-User'),
    path('auth/register/', RegisterView.as_view(), name='Resister-User'),
]