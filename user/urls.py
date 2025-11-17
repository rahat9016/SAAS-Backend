from django.urls import path
from .views import RegisterAPIView

urlpatterns = [
    path("register/", RegisterAPIView.as_view(), name="register"),
    # path("login/", LoginAPIView.as_view(), name="login"),
    # path('verify-account/', VerifyOTPAPIView.as_view(), name="verify_account")
]
