from .serializers import UserSerializer, UserRegisterSerializer, UserLoginSerializer
from .models import User
from rest_framework import status
from rest_framework.views import APIView
from django.contrib.auth import get_user_model
from utils.response import error_response, success_response
from utils.SwaggerResponse import SuccessResponseSerializer, ErrorResponseSerializer
from utils.flatten_errors import flatten_errors
import re
from drf_spectacular.utils import extend_schema, OpenApiResponse
from rest_framework_simplejwt.tokens import RefreshToken

User = get_user_model()


# Create your views here.
class RegisterView(APIView):
    
    @extend_schema(
        request=UserRegisterSerializer,
        responses={
            201: OpenApiResponse(
                response=SuccessResponseSerializer,
                description="User created successfully.",
            ),
            400: OpenApiResponse(
                response=ErrorResponseSerializer, description="Validation error."
            ),
        },
        description="Register a user with phone, first_name, last_name, and password",
    )
    def post(self, request):
        serializer = UserRegisterSerializer(data=request.data)

        if not serializer.is_valid():
            errors = flatten_errors(serializer.errors)
            return error_response(
                message="Validation error. Required fields missing.",
                errors=errors,
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        data = request.data
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
                message="E-mail already registered.",
                errors={"email": "E-mail already registered."},
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        user = User.objects.create_user(
            phone=data["phone"],
            password=data["password"],
            first_name=data["first_name"],
            last_name=data["last_name"],
            email=email,
            is_active=True 
        )

        serializers = UserSerializer(user)

        return success_response(
            message="User Created Successfully.",
            data=serializers.data,
            status_code=status.HTTP_201_CREATED,
        )


class LoginView(APIView):
    def post(self, request):
        data = request.data
        serializer = UserLoginSerializer(data=data)

        if not serializer.is_valid():
            errors = flatten_errors(serializer.errors)
            return error_response(
                message="Validation error. Required fields missing.",
                errors=errors,
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        phone = serializer.validated_data["phone"]
        password = serializer.validated_data["password"]

        if not re.fullmatch(r"^01[0-9]{9}$", phone):
            return error_response(
                message="Invalid phone number format",
                errors={"phone": "Please provide the valid phone number."},
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        try:
            user = User.objects.get(phone=phone)
        except User.DoesNotExist:
            return error_response(
                message="Phone number not registered.",
                errors={"phone": "No user found with this phone number."},
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        if not user.check_password(password):
            return error_response(
                message="Incorrect password.",
                errors={"password": "Wrong password."},
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        print(user)
        # generate access and refresh token
        refresh = RefreshToken.for_user(user)
        access = refresh.access_token

        user_data = UserSerializer(user).data

        return success_response(
            message="User Login Successfully.",
            data={"refresh": str(refresh), "access": str(access), "user": user_data},
            status_code=status.HTTP_200_OK,
        )
