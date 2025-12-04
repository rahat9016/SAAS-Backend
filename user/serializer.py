from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from phonenumber_field.serializerfields import PhoneNumberField
from django.contrib.auth import get_user_model, authenticate
from django.utils.translation import gettext as _
from .models import User

User = get_user_model()


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


class OTPVerifySerializer(serializers.Serializer):
    otp = serializers.CharField(required=True)
    email = serializers.EmailField(required=True)

