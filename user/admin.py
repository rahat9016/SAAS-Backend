from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User, Profile, Address


class ProfileInline(admin.StackedInline):

    model = Profile
    can_delete = False
    verbose_name_plural = "Profile"
    fk_name = "user"


@admin.register(User)
class UserAdmin(BaseUserAdmin):

    inlines = [ProfileInline]
    list_display = ("id","email", "phone", "role", "is_staff", "is_active", "is_superuser", "created_at")
    list_filter = ("role", "is_staff", "is_active", "is_superuser")
    search_fields = ("email", "phone")
    ordering = ("-created_at",)
    fieldsets = (
        (None, {"fields": ("email", "password")}),
        ("Personal Info", {"fields": ("phone", "role")}),
        ("Permissions", {"fields": ("is_staff", "is_active", "is_superuser", "groups", "user_permissions")}),
        ("Important Dates", {"fields": ("last_login", "created_at")}),
    )
    add_fieldsets = (
        (None, {
            "classes": ("wide",),
            "fields": ("email", "password1", "password2", "is_staff", "is_active", "role"),
        }),
    )
    readonly_fields = ("created_at", "updated_at")


@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):

    list_display = ("user", "first_name", "last_name", "username")
    search_fields = ("first_name", "last_name", "user__email")


@admin.register(Address)
class AddressAdmin(admin.ModelAdmin):

    list_display = ("id","full_name", "user", "phone", "address_type", "country", "city", "is_default")
    list_filter = ("address_type", "country", "city", "is_default")
    search_fields = ("full_name", "user__email", "phone", "street_address", "area", "zip_code")
    ordering = ("-created_at",)
