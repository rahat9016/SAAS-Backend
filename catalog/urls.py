from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import CategoryViewSet, SubCategoryViewSet,CategoryTreeAPIView,BrandViewSet

router = DefaultRouter()
router.register(r'categories', CategoryViewSet, basename='category')
router.register(r'sub-categories', SubCategoryViewSet, basename='subcategory')
router.register(r'brand', BrandViewSet, basename='brand')

urlpatterns = [
    path("categories/tree/", CategoryTreeAPIView.as_view(), name="category-tree"),
    path('', include(router.urls)),
]
