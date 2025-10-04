from django.urls import path
from .views import RegisterView, LoginView, ProfileView, TokenRefreshView

urlpatterns = [
    path("auth/login/", LoginView.as_view(), name="Login-User"),
    path("auth/register/", RegisterView.as_view(), name="Resister-User"),
    path("auth/refresh-token/", TokenRefreshView.as_view(), name="Refresh Token"),
    path("user/profile/", ProfileView.as_view(), name="Profile-View"),
]
