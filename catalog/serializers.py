from rest_framework import serializers
from .models import Category, SubCategory, Brand
from PIL import Image
import os

ALLOWED_EXTENSIONS = [".png", ".svg",".jpg"]
MIN_WIDTH = 32
MIN_HEIGHT = 32
MAX_WIDTH = 256
MAX_HEIGHT = 256


def validate_icon_file(value):
    if not value:
        return value

    ext = os.path.splitext(value.name)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise serializers.ValidationError("Icon must be PNG or SVG format.")

    if ext == [".png", ".jpg"]:
        try:
            img = Image.open(value)
            width, height = img.size
        except Exception:
            raise serializers.ValidationError("Invalid image file.")

        if width < MIN_WIDTH or height < MIN_HEIGHT:
            raise serializers.ValidationError(
                f"Icon is too small. Minimum size is {MIN_WIDTH}x{MIN_HEIGHT}px."
            )

        if width > MAX_WIDTH or height > MAX_HEIGHT:
            raise serializers.ValidationError(
                f"Icon is too large. Maximum size is {MAX_WIDTH}x{MAX_HEIGHT}px."
            )

    return value


class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = "__all__"

    def validate_icon(self, value):
        return validate_icon_file(value)


class SubCategorySerializer(serializers.ModelSerializer):
    parent_name = serializers.CharField(
        source="parent_category.name", read_only=True
    )

    class Meta:
        model = SubCategory
        fields = "__all__"

    def validate_parent_category(self, value):
        if not value:
            raise serializers.ValidationError("Parent category is required.")
        return value

    def validate_icon(self, value):
        return validate_icon_file(value)



class SubCategoryTreeSerializer(serializers.ModelSerializer):
    class Meta:
        model = SubCategory
        fields = ["id", "name", "description", "icon"]


class CategoryTreeSerializer(serializers.ModelSerializer):
    subcategories = SubCategoryTreeSerializer(
        many=True,
        read_only=True
    )

    class Meta:
        model = Category
        fields = ["id", "name", "description", "icon", "subcategories"]



class BrandSerializer(serializers.ModelSerializer):
    class Meta:
        model = Brand
        fields = "__all__"

    def validate_icon(self, value):
        return validate_icon_file(value)