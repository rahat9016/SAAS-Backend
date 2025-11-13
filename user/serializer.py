from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from phonenumber_field.serializerfields import PhoneNumberField
from django.contrib.auth import authenticate, get_user_model
from django.utils.translation import gettext as _
from .models import User, Profile

User = get_user_model()


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
        first_name = validated_data.pop("first_name")
        last_name = validated_data.pop("last_name")
        phone = validated_data.pop("phone", None)
        email = validated_data.pop("email")
        password = validated_data.pop("password")

        user = User.objects.create(
            email=email,
            phone=phone,
            password=password,
            is_active=False,  # User must verify OTP to active account
        )

        # Create the profile
        Profile.objects.create(user=user, first_name=first_name, last_name=last_name)
        return user

    def to_representation(self, instance):
        profile = getattr(instance, 'profile', None)
        return {
            "id": str(instance.id),
            "email": str(instance.email),
            "phone": str(instance.phone),
            "is_active": instance.is_active,
            "first_name": profile.first_name if profile else "",
            "last_name": profile.last_name if profile else "",
        }
        

    

class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(
        write_only=True, min_length=6, style={"input_type": "password"}
    )

    def validate(self, attrs):
        email = attrs.get("email")
        password = attrs.get("password")

        if not email and password:
            raise serializers.ValidationError(_("Email and password is required."))

        user = authenticate(email=email, password=password)

        if not user:
            raise serializers.ValidationError(
                _("Invalided credentials. Please check your email and password")
            )

        if not user.is_active:
            raise serializers.ValidationError(_("Your account not activated."))

        attrs["user"] = user
        return attrs

    def to_representation(self, instance):
        print("instance", instance)
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


class VerifyOTPSerializer(serializers.ModelSerializer):
    otp = serializers.CharField(required=True, max_length=6)
    email= serializers.EmailField(required=True)
    