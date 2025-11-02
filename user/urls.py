from django.urls import path
from .views import RegisterAPIView, SendOTPAPIView, LoginAPIView
urlpatterns = [
    path("register/", RegisterAPIView.as_view(), name="register"),
    path("login/", LoginAPIView.as_view(), name="login"),
    path("send-otp/", SendOTPAPIView.as_view(), name="Send OTP"),
]
