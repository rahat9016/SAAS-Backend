from django.db import transaction
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from drf_spectacular.openapi import AutoSchema
from rest_framework import status
from django.utils.translation import gettext as _
from .serializer import UserRegisterSerializer
# from .models import User
from core.services.email.otp_services import OTPEmailService

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
                user = serializer.save()
                print("check user in the try except", user)
                email_service = OTPEmailService()
                email = user.email
                user_name = user.email.split('@')[0]
                
                otp_sent = email_service.sent_otp(email, purpose="registration", user_name=user_name)
                if otp_sent:
                    print(f"OTP sent successfully to {email}")
                else:
                    print(f"Failed to send OTP to {email}")

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
            return Response(
                {
                    "success": False,
                    "status": status.HTTP_400_BAD_REQUEST,
                    "message": _("User registration failed."),
                    "error": str(e),
                    "data": None,
                }
            )

