from django.urls import path

from .views import (
    ChangePasswordAPIView,
    LoginAPIView,
    RefreshTokenAPIView,
    RegisterAPIView,
    ResendOTPAPIView,
    VerifyAccountAPIView,
    VerifyOTPAPIView,
    GoogleSignInAPIView
)

app_name = "users"

urlpatterns = [
    path("register/", RegisterAPIView.as_view(), name="register"),
    path("login/", LoginAPIView.as_view(), name="login"),
    path("refresh-token/", RefreshTokenAPIView.as_view(), name="refresh_token"),
    path("verify-account/", VerifyAccountAPIView.as_view(), name="verify_account"),
    path("resend-otp/", ResendOTPAPIView.as_view(), name="resend_otp"),
    path("verify-otp/", VerifyOTPAPIView.as_view(), name="verify_otp"),
    path("change-password/", ChangePasswordAPIView.as_view(), name="change_password"),
    path("auth/google/", GoogleSignInAPIView.as_view(), name="google-signin")
]
