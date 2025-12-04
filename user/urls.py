from django.urls import path
from .views import RegisterAPIView, LoginAPIView, OTPVerifyAPIView

app_name = "users"
urlpatterns = [
    path("register/", RegisterAPIView.as_view(), name="register"),
    path("login/", LoginAPIView.as_view(), name="login"),
    path("verify-account/", OTPVerifyAPIView.as_view(), name="verify_account"),
]
