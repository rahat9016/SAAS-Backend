from rest_framework.permissions import AllowAny
from .serializers import UserSerializer, UserRegisterSeralizer
from .models import User
from rest_framework import status
from rest_framework.views import APIView
from django.contrib.auth import get_user_model
from utils.response import error_response, success_response
from utils.SwaggerResponse import SuccessResponseSeralizer, ErrorResponseSeralizer
from utils.flatten_errors import flatten_errors
import re
from drf_spectacular.utils import extend_schema, OpenApiResponse

User = get_user_model()


# Create your views here.
class RegisterView(APIView):
    @extend_schema(
        request=UserRegisterSeralizer,
        responses={
            201: OpenApiResponse(
                response=SuccessResponseSeralizer,
                description="User created successfully.",
            ),
            400: OpenApiResponse(
                response=ErrorResponseSeralizer, description="Validation error."
            ),
        },
        description="Register a user with phone, first_name, last_name, and password",
    )
    def post(self, request):

        serializer = UserRegisterSeralizer(data=request.data)

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
            status_code=status.HTTP_201_CREATED,
        )
