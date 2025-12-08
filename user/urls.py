from django.urls import path
from .views import (
    RegisterAPIView,
    LoginAPIView,
    OTPVerifyAPIView,
    RefreshTokenAPIView,
    ResendOTPAPIView,
)

app_name = "users"
urlpatterns = [
    path("register/", RegisterAPIView.as_view(), name="register"),
    path("login/", LoginAPIView.as_view(), name="login"),
    path("refresh-token/", RefreshTokenAPIView.as_view(), name="refresh_token"),
    path("verify-account/", OTPVerifyAPIView.as_view(), name="verify_account"),
    path("resend-otp/", ResendOTPAPIView.as_view(), name="resend_otp"),
]
