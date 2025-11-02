from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from phonenumber_field.serializerfields import PhoneNumberField
from django.contrib.auth import authenticate, get_user_model
from django.utils.translation import gettext as _
from django.db import transaction
from .models import User, Profile
from .email_services import EmailService

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

            self._send_register_otp(email)

        return user

    def _send_register_otp(self, email):
        try:
            email_service = EmailService()
            otp_sent = email_service.sent_otp(email, "registration")
            if not otp_sent:
                print(f"⚠️ OTP sending failed for {email}")
        except Exception as e:
            print(f"Error int otp sending {str(e)}")

    def to_representation(self, instance):
        profile_instance = instance.profile
        return {
            "id": str(instance.id),
            "email": str(instance.email),
            "phone": str(instance.phone),
            "is_active": instance.is_active,
            "first_name": profile_instance.first_name,
            "last_name": profile_instance.last_name,
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
