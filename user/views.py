import logging

from django.contrib.auth import authenticate
from django.db import transaction
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework.exceptions import PermissionDenied
from rest_framework_simplejwt.tokens import RefreshToken

from core.services.email.otp_services import OTPEmailService
from core.utils.response import APIResponse

from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from django.contrib.auth import get_user_model
from django.conf import settings
from .models import Profile, User
from .serializer import (
    ChangePasswordSerializer,
    LoginSerializer,
    RefreshTokenSerializer,
    ResendOTPSerializer,
    UserRegisterSerializer,
    VerifySerializer,
    UserProfileSerializer
)
from .permisiions import IsAdminOrSelf


User = get_user_model()

logger = logging.getLogger(__name__)



class GoogleSignInAPIView(APIView):

    def post(self, request):
        token = request.data.get("token")
        if not token:
            return APIResponse.validation_error(
                errors={"token": ["Google token is required"]}
            )
        try:
            idinfo = id_token.verify_oauth2_token(
                token,
                google_requests.Request(),
                settings.GOOGLE_CLIENT_ID
            )
            email = idinfo.get("email")
            if not email:
                return APIResponse.validation_error(
                    errors={"email": ["Email not found in Google token"]}
                )
            user, created = User.objects.get_or_create(
                email=email,
                defaults={
                    "is_active": True
                }
            )
            refresh = RefreshToken.for_user(user)
            return APIResponse.success(
                message="Google sign-in successful",
                data={
                    "user": {
                        "id": str(user.id),
                        "email": user.email,
                    },
                    "tokens": {
                        "access": str(refresh.access_token),
                        "refresh": str(refresh),
                    }
                },
                status=status.HTTP_200_OK
            )
        except ValueError:
            return APIResponse.validation_error(
                errors={"token": ["Invalid or expired Google token"]}
            )

        except Exception as e:
            # 7️⃣ Any unexpected error
            return APIResponse.server_error(
                message="Google sign-in failed",
                data=str(e)
            )



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
            validated_data = serializer.validated_data
            first_name = validated_data["first_name"]
            last_name = validated_data["last_name"]
            email = validated_data["email"]
            password = validated_data["password"]
            phone = validated_data.get("phone")

            if User.objects.filter(email=email).exists():
                return APIResponse.conflict("User with this email already exists.")

            with transaction.atomic():
                user = User.objects.create_user(
                    email=email,
                    phone=phone,
                    password=password,
                    is_active=False,
                )
                Profile.objects.create(
                    user=user, first_name=first_name, last_name=last_name
                )

            email_service = OTPEmailService()
            email_service.sent_otp(email, user_name=first_name)

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
            return APIResponse.unauthorized("Invalid email or password.")

        except Exception as e:
            logger.exception(f"Login failed: {str(e)}")
            return APIResponse.server_error(str(e))


class RefreshTokenAPIView(APIView):
    # 1. If refresh token not pass then show an error
    # 2. If token has valid date
    # 3. do generate new access token
    # 4. If token hasn't valid time show and error. Token expired
    # 5. if anyhow case failed show error. token not generated.
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
            APIResponse.server_error("Token refresh failed")


class VerifyAccountAPIView(APIView):
    permission_classes = [AllowAny]
    serializer_class = VerifySerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        if not serializer.is_valid():
            return APIResponse.validation_error(serializer.errors, "Invalid data")

        email = serializer.validated_data["email"]
        otp = serializer.validated_data["otp"]

        try:
            user = User.objects.get(email=email)
            otp_service = OTPEmailService()
            success, message = otp_service.verify_otp(email, otp)

            if not success:
                return APIResponse.error(message)

            # OTP matched → activate the account
            user.is_active = True
            user.save()

            return APIResponse.success("Your account has been verified")

        except User.DoesNotExist:
            return APIResponse.unauthorized("Please provide valid email.")

        except Exception as e:
            logger.error(f"Verify Account: {str(e)}")
            return APIResponse.server_error("Account not activated. Please try again.")


class ResendOTPAPIView(APIView):
    """ """

    permission_classes = [AllowAny]
    serializer_class = ResendOTPSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        if not serializer.is_valid():
            return APIResponse.validation_error(
                serializer.errors, "Resend OTP validation failed."
            )

        email = serializer.validated_data["email"]

        otp_service = OTPEmailService()
        allowed, wait_time = otp_service.can_resend_otp(email)

        if not allowed:
            return APIResponse.error(
                f"Please wait for {wait_time} seconds before requesting another OTP.",
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )
        try:
            otp_sent = otp_service.sent_otp(email)

            if not otp_sent:
                logger.error("Failed to send OTP")
                raise Exception("OTP sending failed")

        except Exception as e:
            logger.exception(f"Resend OTP Failed: {str(e)}")
            return APIResponse.server_error("Resend OTP Failed.")

        return APIResponse.success("A new OTP has been sent successfully. ")


class VerifyOTPAPIView(APIView):
    permission_classes = [AllowAny]
    serializer_class = VerifySerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if not serializer.is_valid():
            return APIResponse.validation_error(serializer.errors, "Invalid OTP data.")

        email = serializer.validated_data["email"]
        otp = serializer.validated_data["otp"]
        print(f"{email} - {otp}")
        try:
            User.objects.get(email=email)
            otp_service = OTPEmailService()
            is_success, message = otp_service.verify_otp(email, otp)
            print("\nis_success ->", is_success)
            print("\nmessage ->", message, "\n")

            if not is_success:
                return APIResponse.error(message)

            return APIResponse.success(message, data={"email": email})

        except User.DoesNotExist:
            return APIResponse.unauthorized("Please provide valid email.")

        except Exception as e:
            logger.exception(f"OTP verification failed: {str(e)}")
            return APIResponse.server_error(f"OTP verification failed. {str(e)}")


class ChangePasswordAPIView(APIView):
    permission_classes = [IsAuthenticated]
    serializer_class = ChangePasswordSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        if not serializer.is_valid():
            return APIResponse.validation_error(
                serializer.errors, "Invalided change password data"
            )

        user = request.user
        current_password = serializer.validated_data["current_password"]
        new_password = serializer.validated_data["new_password"]

        try:
            if not user.check_password(current_password):
                return APIResponse.unauthorized("Incorrect old password")

            user.set_password(new_password)
            user.save()

            return APIResponse.success("Password changed successfully")

        except Exception as e:
            logger.exception(f"Change password failed: {str(e)}")
            return APIResponse.server_error(f"Change password failed. {str(e)}")




class UserProfileModeViewSet(ModelViewSet):
    """
        Allowed actions:
        - GET    /users/        (admin only)
        - GET    /users/{id}/   (admin or self)
        - PATCH  /users/{id}/   (admin or self)
    """
    serializer_class = UserProfileSerializer
    queryset = User.objects.select_related('profile')
    permission_classes = [IsAuthenticated, IsAdminOrSelf]
    http_method_names = ["get", "patch"]

    def get_queryset(self):
        """
            Admin → all users
            Normal user → only self
        """

        user = self.request.user
        if user.is_staff or getattr(user, "role", None) == "admin":
            return self.queryset.all()

        return self.queryset.filter(id=user.id)

    def list(self, request, *args, **kwargs):
        user = self.request.user
        if not (user.is_staff or getattr(user, "role", None) == "admin"):
            raise PermissionDenied("You do not have permission to access this resource.")
        return super().list(request, *args, **kwargs)


