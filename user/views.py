from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from drf_spectacular.openapi import AutoSchema
from rest_framework import status
from django.utils.translation import gettext as _
from .serializer import UserRegisterSerializer, UserLoginSerializer


class RegisterAPIView(APIView):
    """
        Register User
    """
    permission_classes = [AllowAny]
    
    def post(self, request):
        data = request.data
        serializer = UserRegisterSerializer(data=data)

        if serializer.is_valid():
            try:
                serializer.save()
                return Response(
                    {
                        "success": True,
                        "status": status.HTTP_201_CREATED,
                        "message": _("User register successful. Please verify your OTP to active your account."),
                        "data": serializer.data,
                    }
                )
            except Exception as e:
                return Response(
                    {
                        "success": False,
                        "status": status.HTTP_400_BAD_REQUEST,
                        "message": _("User registered failed."),
                        "error": str(e),
                        "data": None,
                    }
                )
        return Response(
            {
                "success": False,
                "status": status.HTTP_400_BAD_REQUEST,
                "message": _("Invalid registered data."),
                "errors": serializer.errors,
                "data": None,
            }
        )


class LoginAPIView(APIView):
    def post(self, request):
        serializer = UserLoginSerializer(data = request.data)
        
        if serializer.is_valid():
            
            return 'ok'
        
        return Response(
            {
                "success": False,
                "status": status.HTTP_400_BAD_REQUEST,
                "message": _("Login field"),
                "errors": serializer.errors,
                "data": None,
            }
        )
        


class SendOTPAPIView(APIView):
    pass

