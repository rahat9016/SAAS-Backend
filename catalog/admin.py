from django.contrib import admin
from .models import Category, SubCategory


@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ("name", "id")
    search_fields = ("name",)
    ordering = ("name",)
    list_per_page = 20

    class SubCategoryInline(admin.TabularInline):
        model = SubCategory
        extra = 0
        fields = ("name", "description", "icon")
        show_change_link = True

    inlines = [SubCategoryInline]


@admin.register(SubCategory)
class SubCategoryAdmin(admin.ModelAdmin):
    list_display = ("name", "parent_category", "id")
    list_filter = ("parent_category",)
    search_fields = ("name", "parent_category__name")
    ordering = ("name",)
    list_per_page = 20
