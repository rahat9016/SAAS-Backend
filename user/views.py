from django.db import transaction
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from core.services.email.otp_services import OTPEmailService
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
            return Response(
                {
                    "success": False,
                    "status": status.HTTP_400_BAD_REQUEST,
                    "message": _("Invalid registered data."),
                    "errors": serializer.errors,
                    "data": None,
                }
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
                    return Response(
                        {
                            "success": False,
                            "status": status.HTTP_400_BAD_REQUEST,
                            "message": _("User with this email already exists."),
                            "data": None,
                        }
                    )
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

            return Response(
                {
                    "success": True,
                    "status": status.HTTP_201_CREATED,
                    "message": _(
                        "User created successfully done. Please check your email to active your account"
                    ),
                    "data": serializer.data,
                }
            )
        except Exception as e:
            logger.error(
                f"Registration failed for {request.data.get('email')}: {str(e)}"
            )
            return Response(
                {
                    "success": False,
                    "status": status.HTTP_400_BAD_REQUEST,
                    "message": _("User registration failed."),
                    "error": str(e),
                    "data": None,
                }
            )


class LoginAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {
                    "success": False,
                    "status": status.HTTP_400_BAD_REQUEST,
                    "message": _("Invalid data."),
                    "errors": serializer.errors,
                    "data": None,
                }
            )

        email = serializer.validated_data["email"]
        password = serializer.validated_data["password"]
        try:
            user = User.objects.get(email=email)
            print(user.id)
            if not user.is_active:
                return Response(
                    {
                        "success": False,
                        "status": status.HTTP_400_BAD_REQUEST,
                        "message": _(
                            "This account is not active. Please active first."
                        ),
                        "data": None,
                    }
                )

            authenticated_user = authenticate(email=email, password=password)
            if not authenticated_user:
                return Response(
                    {
                        "success": False,
                        "status": status.HTTP_401_UNAUTHORIZED,
                        "message": _("Invalid Crendicaial."),
                        "data": None,
                    }
                )

            # Generate token.
            refresh = RefreshToken.for_user(user)
            profile = getattr(user, "profile", None)
            return Response(
                {
                    "success": True,
                    "status": status.HTTP_200_OK,
                    "message": "Login successfully done.",
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
                }
            )
        except User.DoesNotExist:
            return Response(
                {
                    "success": False,
                    "status": status.HTTP_404_NOT_FOUND,
                    "message": _("User with this email does not exist."),
                    "data": None,
                }
            )

        except Exception as e:
            print(e)
            return Response(
                {
                    "success": False,
                    "status": status.HTTP_500_INTERNAL_SERVER_ERROR,
                    "message": _(str(e)),
                    "data": None,
                }
            )


class OTPVerifyAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = OTPVerifySerializer(data=request.data)

        if not serializer.is_valid():
            return Response(
                {
                    "success": False,
                    "status": status.HTTP_400_BAD_REQUEST,
                    "message": _("Invalid data."),
                    "errors": serializer.errors,
                    "data": None,
                }
            )
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
                return Response(
                    {
                        "success": True,
                        "status": status.HTTP_200_OK,
                        "message": message,
                        "data": {"email": email},
                    }
                )
            return Response(
                {
                    "success": False,
                    "status": status.HTTP_400_BAD_REQUEST,
                    "message": message,
                    "data": None,
                }
            )
        except User.DoesNotExist:
            return Response(
                {
                    "success": False,
                    "status": status.HTTP_404_NOT_FOUND,
                    "message": _("User with this email does not exist."),
                    "data": None,
                }
            )

        except Exception as e:
            logger.exception(f"OTP verification failed: {str(e)}")
            return Response(
                {
                    "success": False,
                    "status": status.HTTP_500_INTERNAL_SERVER_ERROR,
                    "message": _("OTP verification failed."),
                    "data": None,
                }
            )
