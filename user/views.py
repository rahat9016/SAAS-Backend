from .serializers import (
    UserSerializer,
    UserRegisterSerializer,
    UserLoginSerializer,
    UserSerializer,
)
from .models import User
from rest_framework import status, permissions
from rest_framework.views import APIView
from django.contrib.auth import get_user_model
from drf_spectacular.utils import extend_schema, OpenApiResponse, OpenApiExample
from drf_spectacular.types import OpenApiTypes
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError

User = get_user_model()


class RegisterView(APIView):
    permission_classes = [permissions.AllowAny]

    @extend_schema(
        request=UserRegisterSerializer,
        responses={
            201: OpenApiResponse(
                description="User created successfully", response=UserSerializer
            ),
            400: OpenApiResponse(description="Invalid input data"),
        },
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
    permission_classes = [permissions.AllowAny]

    @extend_schema(
        request=UserLoginSerializer,
        responses={
            200: OpenApiResponse(
                description="User login successfully", response=UserSerializer
            ),
            400: OpenApiResponse(description="Invalid input data"),
        },
    )
    def post(self, request):
        data = request.data
        serializer = UserLoginSerializer(data=data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data["user"]

        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)

        return Response(
            {
                "success": True,
                "message": "Login successful",
                "data": {
                    "user": UserSerializer(user).data,
                    "access": str(refresh.access_token),
                    "refresh": str(refresh),
                },
            },
            status=status.HTTP_200_OK,
        )


class TokenRefreshView(APIView):
    permission_classes = [permissions.AllowAny]

    @extend_schema(
        request=OpenApiTypes.OBJECT,
        examples=[
            OpenApiExample(
                "Valid Request",
                value={"refresh": "your_refresh_token_here"},
                media_type="application/json",
            )
        ],
        responses={
            200: OpenApiResponse(
                description="Token refreshed successfully",
                response=OpenApiTypes.OBJECT,
                examples=[
                    OpenApiExample(
                        "Success Response",
                        value={
                            "success": True,
                            "message": "Token refreshed successfully",
                            "data": {
                                "access": "new_access_token_here",
                                "refresh": "new_refresh_token_here",
                            },
                        },
                        media_type="application/json",
                    )
                ],
            ),
            400: OpenApiResponse(
                description="Invalid or expired refresh token",
                response=OpenApiTypes.OBJECT,
                examples=[
                    OpenApiExample(
                        "Error Response",
                        value={
                            "success": False,
                            "message": "Invalid or expired refresh token",
                            "data": None,
                        },
                        media_type="application/json",
                    )
                ],
            ),
            401: OpenApiResponse(
                description="Authentication failed", response=OpenApiTypes.OBJECT
            ),
        },
    )
    def post(self, request):
        data = request.data
        refresh_token = data.get("refresh")
        if not refresh_token:
            return Response(
                {
                    "success": False,
                    "message": "Refresh token is required",
                    "data": None,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            refresh = RefreshToken(refresh_token)
            new_access_token = str(refresh.access_token)
            new_fresh_token = str(refresh)
            return Response(
                {
                    "success": True,
                    "message": "Token refreshed successfully",
                    "data": {
                        "access": new_access_token,
                        "refresh": new_fresh_token,
                    },
                },
                status=status.HTTP_200_OK,
            )
        except TokenError as e:
            return Response(
                {
                    "success": False,
                    "message": f"Invalid token or expired refresh token: {str(e)}",
                    "data": None,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Exception as e:
            return Response(
                {
                    "success": False,
                    "message": "An error occurred while refreshing token",
                    "data": None,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )


class ProfileView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        serializer = UserSerializer(request.user)
        return Response(
            {"success": True, "message": "Profile retrieved", "data": serializer.data},
            status=status.HTTP_200_OK,
        )
