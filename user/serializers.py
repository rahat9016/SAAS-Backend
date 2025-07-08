from rest_framework import serializers
from django.utils.translation import gettext_lazy as _
from django.contrib.auth import get_user_model
from django.core.validators import RegexValidator

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


class UserRegisterSerializer(serializers.Serializer):
    first_name = serializers.CharField(max_length=255)
    last_name = serializers.CharField(max_length=255)
    email = serializers.EmailField(required=False, allow_null=True)
    phone = serializers.CharField(
        max_length=15,
        validators=[
            RegexValidator(
                regex=r"^01[0-9]{9}$",
                message="Phone number must start with '01' and be 11 digits",
            )
        ],
    )
    password = serializers.CharField(write_only=True, min_length=1)
    

    def validate_phone(self, value):
        if User.objects.filter(phone=value).exists():
            raise serializers.ValidationError('Phone number already registered.')
        return value
    
    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError('E-mail already registered.')
        return value


class UserLoginSerializer(serializers.Serializer):
    phone = serializers.CharField()
    password = serializers.CharField()
