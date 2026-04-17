from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model 
from rest_framework.generics import GenericAPIView
from rest_framework.exceptions import NotFound, AuthenticationFailed
from rest_framework.permissions import AllowAny
from core.services.email.otp_services import OTPEmailService
User = get_user_model()

class TokenMixins:
    """ Generate jwt token for a user """
    @staticmethod
    def generate_token(user):
        refresh = RefreshToken.for_user(user)
        return {
            "access": str(refresh.access_token),
            "refresh": str(refresh)
        }


class UserMixins:
    """ Retrieve active user by email, raising appropriate exceptions. """
    @staticmethod
    def get_active_user_by_email(email):
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise NotFound("User not found.")
        if not user.is_active:
            raise AuthenticationFailed("Account it not active.")
        return user
