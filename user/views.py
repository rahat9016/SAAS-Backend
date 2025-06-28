from django.shortcuts import render
from rest_framework.generics import CreateAPIView
from rest_framework.permissions import AllowAny
from .serializers import UserSerializer
from .models import User
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from django.contrib.auth import get_user_model
from utils.response import error_response, success_response
import re

User = get_user_model()


# Create your views here.
class RegisterView(APIView):
    def post(self, request):
        data = request.data
        required_fields = ["first_name", "last_name", "phone", "password"]

        missing_fields = [field for field in required_fields if not data.get(field)]

        if missing_fields:
            errors = {field: "This field is ruquired" for field in missing_fields}
            return error_response(
                message="Validation error. Required fields missing.",
                errors=errors,
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        # Validation phone format
        phone = data["phone"]
        if not re.fullmatch(r"^01[0-9]{9}$", phone):
            return error_response(
                message="Invalid phone number format",
                errors={"phone": "Please provide the valid phone number."},
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        if User.objects.filter(phone=phone).exists():
            return error_response(
                message="Phone number already registered.",
                errors={"phone": "Phone number already registered."},
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        email = data.get("email")
        if email and User.objects.filter(email=email).exists():
            return error_response(
                message="E-mail alredy registered.",
                errors={"email": "E-mail alredy registered."},
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        user = User.objects.create(
            phone=data["phone"],
            password=data["password"],
            first_name=data["first_name"],
            last_name=data["last_name"],
            email=email,
        )
        user.is_active = True
        user.save()

        serializers = UserSerializer(user)

        return success_response(
            message="User Created Successfully.",
            data=serializers.data,
            status_code=status.HTTP_200_OK,
        )
