from django.utils.translation import gettext as _
from phonenumber_field.serializerfields import PhoneNumberField
from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from .models import User, Profile,Address
import os
from PIL import Image


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


class UserProfileSerializer(serializers.ModelSerializer):
    id = serializers.IntegerField(read_only=True)
    email = serializers.EmailField(read_only=True)
    is_active = serializers.BooleanField(read_only=True)
    first_name = serializers.CharField(source="profile.first_name", required=False)
    last_name = serializers.CharField(source="profile.last_name", required=False)
    username = serializers.CharField(source="profile.username", read_only=True)
    profile_picture = serializers.ImageField(
        source="profile.profile_picture", required=False, allow_null=True
    )
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
    class Meta:
        model = User
        fields = [
            "id",
            "email",
            "phone",
            "role",
            "is_active",
            "created_at",
            "updated_at",
            "first_name",
            "last_name",
            "profile_picture",
            "username",
        ]

    read_only_fields = ["id", "email", "username", "created_at",]

    def validated_profile_picture(self, file):
        if not file:
            return None
        file_size = 2 * 1024 * 1024

        if file.size > file_size:
            raise serializers.ValidationError("Image size must be under 2MB.")
        valid_extensions = [".jpg", ".jpeg", ".png"]
        ext = os.path.splitext(file.name)[1]

        if ext not in valid_extensions:
            raise serializers.ValidationError("Only JPG, JPEG and PNG images are allowed.")

        valid_mimetypes = [".jpg", ".jpeg", ".png"]
        if file.content_type not in valid_mimetypes:
            raise serializers.ValidationError("Only JPG, JPEG and PNG images are allowed.")

        try:
            image = Image.open(file)
        except Exception:
            raise serializers.ValidationError("Invalid image format.")
        file.seek(0)

        return file


    def update(self, instance, validated_data):
        profile_data = validated_data.pop('profile', {})

        # User fields
        for key, value in validated_data.items():
            setattr(instance, key, value)

        instance.save()

        # Profile fields
        profile = getattr(instance, "profile", None)
        for key, value in profile_data.items():
            setattr(profile, key, value)

        profile.save()

        return instance






class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()


class ResetPasswordSerializer(serializers.Serializer):
    new_password = serializers.CharField(write_only=True,min_length=6)
    confirm_password = serializers.CharField()

    def validate(self, data):
        if data["new_password"] != data["confirm_password"]:
            raise serializers.ValidationError("Passwords do not match")
        return data


class AddressSerializer(serializers.ModelSerializer):
    class Meta:
        model = Address
        fields = "__all__"
        read_only_fields = ["id", "user", "created_at", "updated_at"]

    def create(self, validated_data):
        user = self.context['request'].user

        # Check if user already has any addresses
        has_addresses = Address.objects.filter(user=user).exists()

        validated_data['user'] = user
        # Make it default only if no addresses exist
        validated_data['is_default'] = not has_addresses

        address = Address.objects.create(**validated_data)
        return address

    def update(self, instance, validated_data):
        user = self.context['request'].user
        if validated_data.get("is_default", False):
            Address.objects.filter(user=user).exclude(id=instance.id).update(is_default=False)
        return super().update(instance, validated_data)




