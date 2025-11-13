from django.db import transaction
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from drf_spectacular.openapi import AutoSchema
from rest_framework import status
from django.utils.translation import gettext as _
from .serializer import UserRegisterSerializer, UserLoginSerializer, VerifyOTPSerializer
from .email_services import EmailService
from .exception import AccountNotRegisteredException, InvalidCredentialException
from .models import User

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

                email_service = EmailService()
                otp = email_service.sent_otp(user.email, "registration")

                if not otp:
                    raise Exception("Failed to send OTP email")
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


class LoginAPIView(APIView):
    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)

        if serializer.is_valid():

            return "ok"

        return Response(
            {
                "success": False,
                "status": status.HTTP_400_BAD_REQUEST,
                "message": _("Login field"),
                "errors": serializer.errors,
                "data": None,
            }
        )


class VerifyOTPAPIView(APIView):
    """
        Verify OTP for account activation or password reset
    """
    def post(self, request):
        serializer = VerifyOTPSerializer(data=request.data)
        
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
            email = serializer.validate_data['email']
            otp = serializer.validate_data['otp']
            purpose = request.data.get('purpose', 'registration')
            
            email_service = EmailService()
            is_valid, message = email_service.verify_otp(email, otp, purpose)
            
            if not is_valid:
                return Response(
                    {
                        "success": False,
                        "status": status.HTTP_400_BAD_REQUEST,
                        "message": message,
                        "data": None,
                    }
                )
            if purpose == 'registration':
                try:
                    user = User.objects.get(email=email)
                    user.is_active = True
                    user.save()
                    return Response(
                        {
                            "success": True,
                            "status": status.HTTP_200_OK,
                            "message": message,
                            "data": {
                                "email": email,
                                "is_active": True
                            },
                        }
                    )
                except AccountNotRegisteredException as e:
                    raise e
                
        except Exception as e:
            return Response(
                {
                    "success": False,
                    "status": status.HTTP_400_BAD_REQUEST,
                    "message": _("OTP verification failed."),
                    "error": str(e),
                    "data": None,
                }
            )