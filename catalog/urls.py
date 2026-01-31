from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import CategoryViewSet, SubCategoryViewSet

router = DefaultRouter()
router.register(r'categories', CategoryViewSet, basename='category')
router.register(r'sub-categories', SubCategoryViewSet, basename='subcategory')

urlpatterns = [
    path('', include(router.urls)),
]
