from rest_framework import serializers
from django.utils.translation import gettext_lazy as _
from django.contrib.auth import get_user_model
from django.core.validators import RegexValidator
from django.contrib.auth import authenticate

User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    username = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = (
            "id",
            "first_name",
            "last_name",
            "email",
            "phone",
            "profile_picture",
            "role",
            "created_at",
            "username",
        )

    def get_username(self, obj):
        return obj.username


class UserRegisterSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=False, allow_null=True)
    password = serializers.CharField(write_only=True, min_length=1)
    phone = serializers.CharField(
        max_length=15,
        validators=[
            RegexValidator(
                regex=r"^01[0-9]{9}$",
                message="Phone number must start with '01' and be 11 digits",
            )
        ],
    )

    class Meta:
        model = User
        fields = ["first_name", "last_name", "email", "phone", "password"]

    def validate_phone(self, value):
        if User.objects.filter(phone=value).exists():
            raise serializers.ValidationError("Phone number already exists.")
        return value

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("E-mail already registered.")
        return value


class UserLoginSerializer(serializers.Serializer):
    phone = serializers.CharField(required=False, allow_blank=True)
    password = serializers.CharField(required=False, allow_blank=True, write_only=True)

    def validate(self, data):
        phone = data.get("phone")
        password = data.get("password")
        if not phone or not password:
            raise serializers.ValidationError("Phone or password are required.")

        user = authenticate(
            request=self.context.get("request"), phone=phone, password=password
        )

        if not user:
            raise serializers.ValidationError("Invalid phone or password")

        if not user.is_active:
            raise serializers.ValidationError(
                "Your account is inactive. Please contact support"
            )

        data["user"] = user
        return data
