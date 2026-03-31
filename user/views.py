from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.generics import GenericAPIView
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet

from core.services.email.base import BaseEmailService
from core.utils.response import APIResponse

from .models import Address
from .permisiions import IsAdminOrSelf
from .serializer import (
    AddressSerializer,
    ForgotPasswordSerializer,
    ResetPasswordSerializer,
    UserProfileSerializer,
)

User = get_user_model()

@extend_schema(tags=["Users"])
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
    parser_classes = [MultiPartParser, FormParser]
    http_method_names = ["get", "patch"]

    def get_queryset(self):
        return self.queryset

    def retrieve(self, request, *args, **kwargs):

        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return APIResponse.success("User details fetched successfully", serializer.data)

    def list(self, request, *args, **kwargs):
        user = self.request.user
        if not (user.is_staff or getattr(user, "role", None) == "admin"):
            raise PermissionDenied("You do not have permission to access this resource.")

        queryset = self.filter_queryset(self.get_queryset())
        serializer = self.get_serializer(queryset, many=True)
        return APIResponse.success("User list fetched successfully.", data=serializer.data)


    def update(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            serializer = self.get_serializer(instance, data= request.data, partial=True)
            serializer.is_valid(raise_exception=True)

            # if profile picture has in the request then delete previous image, if not found upload new picture
            profile_data = request.data.get("profile") or  {}
            new_picture = profile_data.get('profile_picture') or request.FILES.get('profile_picture')
            profile = getattr(instance, "profile", None)

            if new_picture and profile and profile.profile_picture:
                profile.profile_picture.delete(save=False)

            serializer.save()

            return APIResponse.success("User details updated successfully.", data=serializer.data)

        except ValidationError as e:
            print("ValidationError",e)
            return APIResponse.validation_error(e.detail)

        except Exception as e:
            print("Exception", str(e))
            return APIResponse.server_error(str(e))


class ForgotPasswordAPIView(GenericAPIView):
    serializer_class = ForgotPasswordSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"]

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response(
                {"error": "Wrong email, user not found"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        uid = urlsafe_base64_encode(force_bytes(user.id))
        token = PasswordResetTokenGenerator().make_token(user)

        reset_link = f"{settings.RESET_LINK}/{uid}/{token}/"

        html_message = render_to_string(
            "emails/password_reset_email.html",
            {
                "email": user.email,
                "reset_link": reset_link,
            },
        )

        BaseEmailService()._sent_email_raw(
            subject="Password Reset Request",
            recipient_list=[user.email],
            html_message=html_message,
        )

        return Response(
            {"message": "Password reset email sent"},
            status=status.HTTP_200_OK,
        )


class ResetPasswordAPIView(GenericAPIView):
    serializer_class = ResetPasswordSerializer

    def post(self, request, uidb64, token):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(id=uid)
        except Exception:
            return Response(
                {"error": "Invalid reset link"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        token_generator = PasswordResetTokenGenerator()
        if not token_generator.check_token(user, token):
            return Response(
                {"error": "Token invalid or expired"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        user.set_password(serializer.validated_data["new_password"])
        user.is_active = True
        user.save()

        return Response(
            {"message": "Password reset successful"},
            status=status.HTTP_200_OK,
        )

@extend_schema(tags=["Address"])
class AddressViewSet(ModelViewSet):
    serializer_class = AddressSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Address.objects.filter(user=self.request.user)

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        return APIResponse.success(data=serializer.data, message="User addresses retrieved successfully")

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return APIResponse.success(data=serializer.data, message="Address retrieved successfully")

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        return APIResponse.created(data=serializer.data, message="Address created successfully")

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return APIResponse.success(data=serializer.data, message="Address updated successfully")

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return APIResponse.success(message="Address deleted successfully")