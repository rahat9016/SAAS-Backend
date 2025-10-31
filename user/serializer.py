from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from phonenumber_field.serializerfields import PhoneNumberField
from django.utils.translation import gettext as _
from django.db import transaction
from .models import User, Profile


class UserRegisterSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(required=True, write_only=True)
    last_name = serializers.CharField(required=True, write_only=True)
    password = serializers.CharField(
        write_only=True, min_length=6, style={"input_type": "password"}
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
    email = serializers.EmailField(
        required=True,
        validators=[
            UniqueValidator(
                queryset=User.objects.all(),
                message=_("A user already registered with time email."),
            )
        ],
    )

    class Meta:
        model = User
        fields = ("first_name", "last_name", "phone", "email", "password")

    def create(self, validated_data):
        # Profile-related data আলাদা করে নিচ্ছি
        first_name = validated_data.pop("first_name")
        last_name = validated_data.pop("last_name")
        phone = validated_data.pop("phone", None)
        email = validated_data.pop("email")
        password = validated_data.pop("password")

        with transaction.atomic():
            # Transaction is used to keep database operations atomic.
            # That means either all operations will succeed together
            # or all operations will fail together.
            user = User.objects.create(
                email=email,
                phone=phone,
                password=password,
                is_active=False,  # User must verify OTP to active account
            )

            # Create the profile
            Profile.objects.create(
                user=user, first_name=first_name, last_name=last_name
            )
        return user

    def to_representation(self, instance):
        # Return basic user data after register

        # Prefetch profile
        profile_instance = instance.profile
        return {
            "id": str(instance.id),
            "email": str(instance.email),
            "phone": str(instance.phone),
            "is_active": instance.is_active,
            "first_name": profile_instance.first_name,
            "last_name": profile_instance.last_name,
        }


class SendOTPSerializer(serializers.ModelSerializer):
    """
    Serializer for sending OTP for REGISTRATION (email should not exist)
    """

    email = serializers.EmailField(required=True)

    def validate_email(self, value):
        """
        If email does NOT exist in database (for registration)
        """
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError(
                {
                    "email": "No account found with this email address. Please check your email or register first"
                }
            )
        return value
