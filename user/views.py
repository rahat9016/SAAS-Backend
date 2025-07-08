from .serializers import (
    UserSerializer,
    UserRegisterSerializer,
    UserLoginSerializer,
    UserSerializer,
)
from .models import User
from rest_framework import status
from rest_framework.views import APIView
from django.contrib.auth import get_user_model
from drf_spectacular.utils import extend_schema, OpenApiResponse
from rest_framework.response import Response

User = get_user_model()


class RegisterView(APIView):
    @extend_schema(
        request=UserRegisterSerializer,
        responses={
            201: OpenApiResponse(
                response=UserSerializer,
                description="User created successfully.",
            ),
        },
        description="Register a user with phone, first_name, last_name, and password",
    )
    def post(self, request):
        serializer = UserRegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = User.objects.create_user(
            phone=serializer.validated_data["phone"],
            first_name=serializer.validated_data["first_name"],
            last_name=serializer.validated_data["last_name"],
            email=serializer.validated_data.get("email"),
            password=serializer.validated_data["password"],
            is_active=True,
        )
        return Response(
            {
                "success": True,
                "message": "User created successfully",
                "data": UserSerializer(user).data,
            },
            status=status.HTTP_201_CREATED,
        )


class LoginView(APIView):
    def post(self, request):
        data = request.data
        serializer = UserLoginSerializer(data=data)

        
