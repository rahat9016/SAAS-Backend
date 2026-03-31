from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import (
    AddressViewSet,
    UserProfileModeViewSet,
)

app_name = "users"

router = DefaultRouter()
router.register(r"users", UserProfileModeViewSet, basename="users")
router.register(r'addresses', AddressViewSet, basename='address')

urlpatterns = [
    path("", include(router.urls)),
    # path("auth/forgot-password/", ForgotPasswordAPIView.as_view()),
    # path("auth/reset-password/<uidb64>/<token>/", ResetPasswordAPIView.as_view()),
]