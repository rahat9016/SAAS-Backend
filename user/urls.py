from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    ChangePasswordAPIView,
    LoginAPIView,
    RefreshTokenAPIView,
    RegisterAPIView,
    ResendOTPAPIView,
    VerifyAccountAPIView,
    VerifyOTPAPIView,
    UserProfileModeViewSet,
    GoogleSignInAPIView,
    ForgotPasswordAPIView,
    ResetPasswordAPIView,
    AddressViewSet
)

app_name = "users"

router = DefaultRouter()
router.register(r"users", UserProfileModeViewSet, basename="users")
router.register(r'addresses', AddressViewSet, basename='address')

urlpatterns = [
    # ---------- Auth APIs ----------
    path("", include(router.urls)),
    path("register/", RegisterAPIView.as_view(), name="register"),
    path("login/", LoginAPIView.as_view(), name="login"),
    path("refresh-token/", RefreshTokenAPIView.as_view(), name="refresh_token"),
    path("verify-account/", VerifyAccountAPIView.as_view(), name="verify_account"),
    path("resend-otp/", ResendOTPAPIView.as_view(), name="resend_otp"),
    path("verify-otp/", VerifyOTPAPIView.as_view(), name="verify_otp"),
    path("change-password/", ChangePasswordAPIView.as_view(), name="change_password"),
    path("auth/google/", GoogleSignInAPIView.as_view(), name="google-signin"),
    path("auth/forgot-password/", ForgotPasswordAPIView.as_view()),
    path("auth/reset-password/<uidb64>/<token>/", ResetPasswordAPIView.as_view()),
]
