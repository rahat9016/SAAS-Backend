from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import CategoryViewSet, SubCategoryViewSet,CategoryTreeAPIView

router = DefaultRouter()
router.register(r'categories', CategoryViewSet, basename='category')
router.register(r'sub-categories', SubCategoryViewSet, basename='subcategory')

urlpatterns = [
    path("categories/tree/", CategoryTreeAPIView.as_view(), name="category-tree"),
    path('', include(router.urls)),
]
