from rest_framework import serializers
from .models import Category, SubCategory


class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = "__all__"


class SubCategorySerializer(serializers.ModelSerializer):
    parent_name = serializers.CharField(
        source="parent_category.name", read_only=True
    )

    class Meta:
        model = SubCategory
        fields = "__all__"
