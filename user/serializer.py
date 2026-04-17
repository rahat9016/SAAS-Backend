import os
from PIL import Image
from django.utils.translation import gettext as _
from phonenumber_field.serializerfields import PhoneNumberField
from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from .models import Address, User

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

    def validate_profile_picture(self, file):
        if not file:
            return None

        request = self.context.get("request")    # using self to avoid static warning

        max_size = 2 * 1024 * 1024
        if file.size > max_size:
            raise serializers.ValidationError("Image size must be under 2MB.")

        valid_extensions = [".jpg", ".jpeg", ".png"]
        ext = os.path.splitext(file.name)[1].lower()
        if ext not in valid_extensions:
            raise serializers.ValidationError(
                "Only JPG, JPEG and PNG images are allowed."
            )

        valid_mimetypes = ["image/jpeg", "image/png"]
        if file.content_type not in valid_mimetypes:
            raise serializers.ValidationError("Invalid image type.")

        try:
            image = Image.open(file)
            image.verify()
        except Exception:
            raise serializers.ValidationError("Invalid or corrupted image file.")

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


class UserSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(source="profile.first_name")
    last_name = serializers.CharField(source="profile.last_name")
    class Meta:
        model = User
        fields = ["id", "email", "first_name", "last_name"]

class AddressSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
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




