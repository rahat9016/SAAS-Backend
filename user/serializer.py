from django.utils.translation import gettext as _
from phonenumber_field.serializerfields import PhoneNumberField
from rest_framework import serializers
from rest_framework.validators import UniqueValidator

from .models import Profile, User


class UserRegisterSerializer(serializers.Serializer):
    first_name = serializers.CharField(required=True, max_length=255)
    last_name = serializers.CharField(required=True, max_length=255)
    password = serializers.CharField(write_only=True, min_length=6)

    phone = PhoneNumberField(
        region="BD",
        required=False,
        validators=[
            UniqueValidator(
                queryset=User.objects.all(),
                message=_("A user already registered with this phone number."),
            )
        ],
    )

    email = serializers.EmailField(
        required=True,
        validators=[
            UniqueValidator(
                queryset=User.objects.all(),
                message=_("A user already registered with this email."),
            )
        ],
    )

    def validate(self, data):
        return data


class LoginSerializer(serializers.Serializer):
    password = serializers.CharField(required=True, write_only=True)
    email = serializers.EmailField(required=True)


class VerifySerializer(serializers.Serializer):
    otp = serializers.CharField(required=True, min_length=6, max_length=6)
    email = serializers.EmailField(required=True)


class RefreshTokenSerializer(serializers.Serializer):
    refresh_token = serializers.CharField(required=True)


class ResendOTPSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)


class ChangePasswordSerializer(serializers.Serializer):
    current_password = serializers.CharField(write_only=True, min_length=6)
    new_password = serializers.CharField(write_only=True, min_length=6)
    confirm_password = serializers.CharField(write_only=True, min_length=6)

    def validate(self, data):
        if data["new_password"] != data["confirm_password"]:
            raise serializers.ValidationError(
                {"password": "New password and confirm password doesn't match."}
            )
        return data


class ProfileSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source="username", read_only=True)
    profile_picture = serializers.CharField(read_only=True)

    class Meta:
        model = Profile
        fields = ["id", "username", "first_name", "last_name", "profile_picture"]
        read_only_fields = ["id", "profile_picture"]


class UserSerializer(serializers.ModelSerializer):
    profile = ProfileSerializer(source="profile", required=False)
    email = serializers.EmailField(read_only=True)

    class Meta:
        model = User
        fields = ["id", "email", "phone", "role", "created_at", "updated_at", "profile"]
        read_only_fields = ["email", "created_at", "updated_at"]
