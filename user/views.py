from django.db import transaction
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from core.services.email.otp_services import OTPEmailService
from core.utils.response import APIResponse
from django.utils.translation import gettext as _
from django.contrib.auth import authenticate
from .serializer import UserRegisterSerializer, OTPVerifySerializer, LoginSerializer
from .models import User, Profile

import logging

logger = logging.getLogger(__name__)


class RegisterAPIView(APIView):
    """
    Register User
    """

    permission_classes = [AllowAny]

    def post(self, request):
        data = request.data
        serializer = UserRegisterSerializer(data=data)

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

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if not serializer.is_valid():
            return APIResponse.validation_error(
                serializer.errors, "Invalid login data."
            )

        email = serializer.validated_data["email"]
        password = serializer.validated_data["password"]
        try:
            user = User.objects.get(email=email)
            print(user.id)
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
            return APIResponse.created(
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
            print(e)
            return APIResponse.server_error(str(e))


class OTPVerifyAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = OTPVerifySerializer(data=request.data)

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
