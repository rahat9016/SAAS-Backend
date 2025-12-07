from django.db import transaction
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from core.services.email.otp_services import OTPEmailService
from core.utils.response import APIResponse
from django.utils.translation import gettext as _
from django.contrib.auth import authenticate
from .serializer import (
    UserRegisterSerializer,
    OTPVerifySerializer,
    LoginSerializer,
    RefreshTokenSerializer,
)
from .models import User, Profile

import logging

logger = logging.getLogger(__name__)


class RegisterAPIView(APIView):
    """
    Register User
    """

    permission_classes = [AllowAny]
    serializer_class = UserRegisterSerializer
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if not serializer.is_valid():
            return APIResponse.validation_error(
                serializer.errors, "Invalid registered data."
            )
        try:
            with transaction.atomic():
                validated_data = serializer.validated_data
                first_name = validated_data["first_name"]
                last_name = validated_data["last_name"]
                email = validated_data["email"]
                password = validated_data["password"]
                phone = validated_data.get("phone")

                if User.objects.filter(email=email).exists():
                    return APIResponse.conflict("User with this email already exists.")

                user = User.objects.create_user(  # type: ignore
                    email=email,
                    phone=phone,
                    password=password,
                    is_active=False,
                )
                Profile.objects.create(
                    user=user, first_name=first_name, last_name=last_name
                )
                email_service = OTPEmailService()
                otp_sent = email_service.sent_otp(
                    email, purpose="registration", user_name=first_name
                )
                if not otp_sent:
                    logger.error(f"Failed to send OTP to {user.email}")
                    raise Exception("OTP sending failed")

            return APIResponse.created(
                "User created successfully done. Please check your email to active your account",
                serializer.data,
            )

        except Exception as e:
            logger.error(
                f"Registration failed for {request.data.get('email')}: {str(e)}"
            )
            return APIResponse.error("User registration failed.")


class LoginAPIView(APIView):
    permission_classes = [AllowAny]
    serializer_class = LoginSerializer
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if not serializer.is_valid():
            return APIResponse.validation_error(
                serializer.errors, "Invalid login data."
            )

        email = serializer.validated_data["email"]
        password = serializer.validated_data["password"]
        try:
            user = User.objects.get(email=email)
            if not user.is_active:
                return APIResponse.error(
                    "This account is not active. Please active first."
                )

            authenticated_user = authenticate(email=email, password=password)
            if not authenticated_user:
                return APIResponse.unauthorized("Invalid Credentials.")

            # Generate token.
            refresh = RefreshToken.for_user(user)
            profile = getattr(user, "profile", None)
            return APIResponse.success(
                "Login successfully done.",
                data={
                    "tokens": {
                        "access": str(refresh.access_token),
                        "refresh": str(refresh),
                    },
                    "user": {
                        "id": str(user.id),
                        "email": user.email,
                        "phone": str(user.phone) if user.phone else None,
                        "first_name": profile.first_name if profile else "",
                        "last_name": profile.last_name if profile else "",
                        "role": user.role,
                    },
                },
            )
        except User.DoesNotExist:
            return APIResponse.not_found("User with this email does not exist.")

        except Exception as e:
            logger.exception(f"Login failed: {str(e)}")
            return APIResponse.server_error(str(e))


class OTPVerifyAPIView(APIView):
    permission_classes = [AllowAny]
    serializer_class = OTPVerifySerializer
    
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if not serializer.is_valid():
            return APIResponse.validation_error(serializer.errors, "Invalid OTP data.")

        email = serializer.validated_data["email"]
        otp = serializer.validated_data["otp"]
        purpose = "registration"

        try:
            user = User.objects.get(email=email)
            otp_service = OTPEmailService()
            is_success, message = otp_service.verify_otp(email, otp, purpose)
            if is_success:
                user.is_active = True
                user.save()
                return APIResponse.success(message, data={"email": email})

            # OTP response error
            return APIResponse.error(message)

        except User.DoesNotExist:
            return APIResponse.not_found("User with this email does not exist.")

        except Exception as e:
            logger.exception(f"OTP verification failed: {str(e)}")
            return APIResponse.server_error(f"OTP verification failed. {str(e)}")


class RefreshTokenAPIView(APIView):
    # 1. If refresh token not pass then show an error
    # 2. If token has valid date
    # 3. do generate new access token
    # 4. If token hasn't valid time show and error. Token expired
    # 5. if any how case failed show error. token not generated.
    serializer_class = RefreshTokenSerializer
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if not serializer.is_valid():
            return APIResponse.validation_error(
                serializer.errors, "Refresh token validation failed."
            )
        try:
            refresh_token = serializer.validated_data["refresh_token"]
            refresh = RefreshToken(refresh_token)

            # Is refresh token has expired date
            refresh.check_exp()
            user_id = refresh["user_id"]

            try:
                user = User.objects.get(id=user_id)
                if not user.is_active:
                    return APIResponse.error("This user account not active")

                # Generate new access token
                new_access_token = str(refresh.access_token)
                return APIResponse.success(
                    "Token refreshed successfully",
                    data={
                        "tokens": {
                            "access": new_access_token,
                        },
                    },
                )
            except User.DoesNotExist:
                return APIResponse.not_found("User not found for this token")

        except TokenError as e:
            logger.error(f"Token validation failed: {str(e)}")
            return APIResponse.error("Refresh token has been expired")
        except Exception as e:
            logger.exception(f"Token refresh failed: {str(e)}")
            APIResponse.server_error(f"Token refresh failed")
