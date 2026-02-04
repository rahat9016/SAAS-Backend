from rest_framework import serializers
from .models import Category, SubCategory
from PIL import Image
import os

ALLOWED_FORMATS = ["PNG", "SVG"]
MIN_WIDTH = 32
MIN_HEIGHT = 32
MAX_WIDTH = 256
MAX_HEIGHT = 256

class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = "__all__"

    def validate_icon(self, value):
        if not value:
            return value

        ext = os.path.splitext(value.name)[1].lower()
        if ext not in [".png", ".svg"]:
            raise serializers.ValidationError("Icon must be PNG or SVG format.")

        if ext == ".png":
            img = Image.open(value)
            width, height = img.size
            if width < MIN_WIDTH or height < MIN_HEIGHT:
                raise serializers.ValidationError(
                    f"Icon is too small. Minimum size is {MIN_WIDTH}x{MIN_HEIGHT}px."
                )
            if width > MAX_WIDTH or height > MAX_HEIGHT:
                raise serializers.ValidationError(
                    f"Icon is too large. Maximum size is {MAX_WIDTH}x{MAX_HEIGHT}px."
                )
        return value


class SubCategorySerializer(serializers.ModelSerializer):
    parent_name = serializers.CharField(
        source="parent_category.name", read_only=True
    )

    class Meta:
        model = SubCategory
        fields = "__all__"

    def validate_icon(self, value):
        if not value:
            return value

        ext = os.path.splitext(value.name)[1].lower()
        if ext not in [".png", ".svg"]:
            raise serializers.ValidationError("Icon must be PNG or SVG format.")

        if ext == ".png":
            img = Image.open(value)
            width, height = img.size
            if width < MIN_WIDTH or height < MIN_HEIGHT:
                raise serializers.ValidationError(
                    f"Icon is too small. Minimum size is {MIN_WIDTH}x{MIN_HEIGHT}px."
                )
            if width > MAX_WIDTH or height > MAX_HEIGHT:
                raise serializers.ValidationError(
                    f"Icon is too large. Maximum size is {MAX_WIDTH}x{MAX_HEIGHT}px."
                )
        return value
