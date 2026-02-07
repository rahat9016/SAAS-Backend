from rest_framework.viewsets import ModelViewSet
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework import status
from rest_framework.views import APIView
from .models import Category, SubCategory
from .serializers import CategorySerializer, SubCategorySerializer, CategoryTreeSerializer
from core.utils.response import APIResponse

from rest_framework.permissions import IsAuthenticated

from drf_spectacular.utils import extend_schema

@extend_schema(tags=["Category"])
class CategoryViewSet(ModelViewSet):
    queryset = Category.objects.all()
    serializer_class = CategorySerializer
    parser_classes = [MultiPartParser, FormParser]
    permission_classes = [IsAuthenticated]

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        return APIResponse.success(
            message="Category list fetched successfully",
            data=serializer.data
        )

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return APIResponse.success(
            message="Category details fetched",
            data=serializer.data
        )

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if not serializer.is_valid():
            return APIResponse.validation_error(serializer.errors)

        serializer.save()
        return APIResponse.created(
            message="Category created successfully",
            data=serializer.data
        )

    def partial_update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(
            instance, data=request.data, partial=True
        )
        if not serializer.is_valid():
            return APIResponse.validation_error(serializer.errors)

        serializer.save()
        return APIResponse.success(
            message="Category updated successfully",
            data=serializer.data
        )

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.delete()
        return APIResponse.success(
            message="Category deleted successfully",
            data=None,
            status=status.HTTP_204_NO_CONTENT
        )

@extend_schema(tags=["Sub-Category"])
class SubCategoryViewSet(ModelViewSet):
    queryset = SubCategory.objects.all()
    serializer_class = SubCategorySerializer
    parser_classes = [MultiPartParser, FormParser]
    permission_classes = [IsAuthenticated]

    def list(self, request, *args, **kwargs):
        serializer = self.get_serializer(self.get_queryset(), many=True)
        return APIResponse.success(
            message="Sub-category list fetched",
            data=serializer.data
        )

    def retrieve(self, request, *args, **kwargs):
        serializer = self.get_serializer(self.get_object())
        return APIResponse.success(
            message="Sub-category details fetched",
            data=serializer.data
        )

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if not serializer.is_valid():
            return APIResponse.validation_error(serializer.errors)

        serializer.save()
        return APIResponse.created(
            message="Sub-category created successfully",
            data=serializer.data
        )

    def partial_update(self, request, *args, **kwargs):
        serializer = self.get_serializer(
            self.get_object(),
            data=request.data,
            partial=True
        )
        if not serializer.is_valid():
            return APIResponse.validation_error(serializer.errors)

        serializer.save()
        return APIResponse.success(
            message="Sub-category updated successfully",
            data=serializer.data
        )

    def destroy(self, request, *args, **kwargs):
        self.get_object().delete()
        return APIResponse.success(
            message="Sub-category deleted successfully",
            data=None,
            status=status.HTTP_204_NO_CONTENT
        )


@extend_schema(tags=["Category"])
class CategoryTreeAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        queryset = Category.objects.prefetch_related("subcategories")
        serializer = CategoryTreeSerializer(queryset, many=True)

        if not serializer.data:
            return APIResponse.success(
                message="No categories found",
                data=[]
            )

        return APIResponse.success(
            message="Category tree fetched successfully",
            data=serializer.data
        )
