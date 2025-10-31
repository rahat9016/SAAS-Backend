from django.urls import path
from .views import RegisterAPIView, SendOTPAPIView

urlpatterns = [
    path("register/", RegisterAPIView.as_view(), name="register"),
    path("send-otp/", SendOTPAPIView.as_view(), name="Send OTP"),
]
