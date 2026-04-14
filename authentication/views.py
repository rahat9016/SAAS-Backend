import requests
from django.conf import settings
from django.contrib.auth import authenticate
from django.core.files.base import ContentFile
from django.db import transaction
from drf_spectacular.utils import extend_schema
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token
from rest_framework import status
from rest_framework.exceptions import (
    APIException,
    AuthenticationFailed,
    ValidationError,
NotFound
)
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken

from core.messages import AuthMessages
from authentication.mixins import TokenMixins, UserMixins
from core.services.email.otp_services import OTPEmailService
from core.utils.response import APIResponse
from core.utils.urls import get_absolute_url
from user.models import Profile, User

from .serializer import (
    ChangePasswordSerializer,
    GoogleSignInSerializer,
    LoginSerializer,
    RefreshTokenSerializer,
    ResendOTPSerializer,
    UserRegisterSerializer,
    VerifySerializer,
)



class OTPBaseView(GenericAPIView):
    permission_classes = [AllowAny]
    otp_service_class = OTPEmailService

    def get_otp_service(self):
        return self.otp_service_class()

    def send_otp(self, email, user_name=None):
        service = self.get_otp_service()
        return service.sent_otp(email, user_name=user_name)

    def verify_otp(self, email, otp):
        service = self.get_otp_service()
        return service.verify_otp(email, otp)

@extend_schema(
    tags=["Auth"],
    request=GoogleSignInSerializer,
    responses={200: dict},
)
class GoogleSignInAPIView(TokenMixins, GenericAPIView):
    serializer_class = GoogleSignInSerializer
    permission_classes = [AllowAny]

    @transaction.atomic
    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        token = serializer.validated_data["token"]
        try:
            _signing_info = id_token.verify_oauth2_token(
                token, google_requests.Request(), settings.GOOGLE_CLIENT_ID
            )
        except ValueError:
            raise ValidationError({"token": AuthMessages.TOKEN_INVALID})
        email = _signing_info.get("email")
        if not email:
            raise ValidationError({"email": "Email not found in Google token"})
        user, created = User.objects.get_or_create(
            email=email, defaults={"is_active": True}
        )
        if not user.is_active:
            user.is_active = True
            user.save()

        profile, _ = Profile.objects.get_or_create(user=user)
        profile.first_name = _signing_info.get("given_name", "")
        profile.last_name = _signing_info.get("family_name", "")
        if picture := _signing_info.get("picture"):
            self._download_profile_picture(profile, picture)
        profile.save()
        tokens = self.generate_token(user)
        return APIResponse.success(
            AuthMessages.GOOGLE_SIGNIN_SUCCESS,
            data={
                "user": {
                    "id": str(user.id),
                    "email": user.email,
                    "first_name": profile.first_name,
                    "last_name": profile.last_name,
                },
                "tokens": tokens,
            },
        )
    @staticmethod
    def _download_profile_picture(profile, url):
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                profile.profile_picture.save(
                    f"{profile.user.id}.jpg",
                    ContentFile(response.content),
                    save=False,
                )
        except Exception as e:
            print(str(e))


@extend_schema(tags=["Auth"])
class RegisterAPIView(GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = UserRegisterSerializer

    @transaction.atomic
    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated = serializer.validated_data

        try:
            user = User.objects.create_user(
                email=validated["email"],
                phone=validated.get("phone"),
                password=validated["password"],
                is_active=False,
            )
            Profile.objects.create(
                user=user,
                first_name=validated["first_name"],
                last_name=validated["last_name"],
            )

            email_service = OTPEmailService()
            email_service.sent_otp(
                validated["email"], user_name=validated["first_name"]
            )

            return APIResponse.created(
                AuthMessages.REGISTRATION_SUCCESS, data={"email": user.email}
            )

        except Exception as e:
            print("Registration failed", str(e))
            raise APIException(AuthMessages.REGISTRATION_FAILED)


@extend_schema(tags=["Auth"])
class LoginAPIView(TokenMixins, UserMixins, GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated = serializer.validated_data

        user = self.get_active_user_by_email(validated["email"])
        authenticated = authenticate(email=validated["email"], password=validated["password"])
        
        if not authenticated:
            raise AuthenticationFailed(AuthMessages.INVALID_CREDENTIALS)

        # Generate tokens using TokenMixin
        tokens = self.generate_token(user)
        
        profile = user.profile
        profile_picture_url = (
            get_absolute_url(request, profile.profile_picture.url) if profile.profile_picture else None
        )

        return APIResponse.success(
            AuthMessages.LOGIN_SUCCESS,
            data={
                "tokens": tokens,
                "user": {
                    "id": str(user.id),
                    "email": user.email,
                    "phone": str(user.phone) if user.phone else None,
                    "first_name": profile.first_name,
                    "last_name": profile.last_name,
                    "profile_picture": profile_picture_url,
                },
            },
        )
        
@extend_schema(tags=["Auth"])
class RefreshTokenAPIView(GenericAPIView):
    serializer_class = RefreshTokenSerializer
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        refresh_token = serializer.validated_data["refresh_token"]
        try:
            refresh = RefreshToken(refresh_token)
            refresh.check_exp()
            user_id = refresh["user_id"]
            user = User.objects.get(id=user_id)
            if not user.is_active:
                raise AuthenticationFailed("User account not active")

            new_access_token = str(refresh.access_token)
            return APIResponse.success(
                "Token refreshed successfully",
                data={"access": new_access_token},
            )
        except TokenError as e:
            raise AuthenticationFailed(str(e))
        except User.DoesNotExist:
            raise AuthenticationFailed("User not found for this token")


@extend_schema(tags=["Auth"])
class VerifyAccountAPIView(OTPBaseView):
    serializer_class = VerifySerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"]
        otp = serializer.validated_data["otp"]

        user = User.objects.get(email=email)
        success, message = self.verify_otp(email, otp)
        if not success:
            raise ValidationError(message)

        user.is_active = True
        user.save()
        return APIResponse.success("Your account has been verified")

@extend_schema(tags=["Auth"])
class ResendOTPAPIView(OTPBaseView):
    serializer_class = ResendOTPSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"]
        if not User.objects.filter(email=email).exists():
            raise NotFound(AuthMessages.USER_NOT_FOUND)

        service = self.get_otp_service()
        allowed, wait_time = service.can_resend_otp(email)
        if not allowed:
            return APIResponse.error(
                f"Please wait for {wait_time} seconds before requesting another OTP.",
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        self.send_otp(email)
        return APIResponse.success("A new OTP has been sent successfully.")

@extend_schema(tags=["Auth"])
class VerifyOTPAPIView(OTPBaseView):
    serializer_class = VerifySerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"]
        otp = serializer.validated_data["otp"]

        if not User.objects.filter(email=email).exists():
            raise NotFound(AuthMessages.USER_NOT_FOUND)

        success, message = self.verify_otp(email, otp)
        if not success:
            raise ValidationError(message)

        return APIResponse.success(message, data={"email": email})

@extend_schema(tags=["Auth"])
class ChangePasswordAPIView(GenericAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = ChangePasswordSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = request.user
        current_password = serializer.validated_data["current_password"]
        new_password = serializer.validated_data["new_password"]

        if not user.check_password(current_password):
            raise AuthenticationFailed("Incorrect old password")

        user.set_password(new_password)
        user.save()
        return APIResponse.success("Password changed successfully")