from django.contrib import admin
from .models import Category


# Register your models here.
@admin.register(Category)
class UserAdmin(admin.ModelAdmin):
    list_display = ["title"]
    list_per_page = 10
