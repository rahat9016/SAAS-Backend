import uuid
from django.db import models
from django_countries.fields import CountryField
from phonenumber_field.modelfields import PhoneNumberField
from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    PermissionsMixin,
)

class UserRole(models.TextChoices):
    CUSTOMER = "customer", "Customer"
    ADMIN = "admin", "Admin"
    VENDOR = (
        "vendor",
        "Vendor",
    )
    MODERATOR = "moderator", "Moderator"


class UserManager(BaseUserManager):
    def create_user(
        self, email, password=None, **extra_fields
    ):
        if not email:
            raise ValueError("Email is required.")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_active", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields["role"] = UserRole.ADMIN

        return self.create_user(email=email, password=password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    """
    Custom User Model using phone number as primary identifier.
    Inherits from Django's AbstractBaseUser and PermissionsMixin for authentication and authorization.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(max_length=255, unique=True)
    phone = PhoneNumberField(region="BD", unique=True, blank=True, null=True)
    role = models.CharField(max_length=25, choices=UserRole, default=UserRole.CUSTOMER)
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []
    def __str__(self):
        return self.email


class Profile(models.Model):
    """
    User Profile model   extending the core User model with additional personal information.
    Maintains a one-to-one relationship with the User model for separated authentication and profile data.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="profile")
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    profile_picture = models.ImageField(upload_to="profile/", blank=True, null=True)
    
    def __str__(self):
        return self.first_name + " " + self.last_name

    @property
    def username(self):
        return f"{self.first_name}_{self.last_name}_{self.id.hex[:2]}"


class AddressType(models.TextChoices):
    SHIPPING = "shipping", "Shipping"
    BILLING = "billing", "Billing"
    HOME = "home", "Home"
    OFFICE = "office", "Office"


class Address(models.Model):
    """
    Stores multiple addresses per user for different purposes (shipping, billing, etc.).
    This supports scenarios like delivering to office but billing at home.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    full_name = models.CharField(max_length=255)
    phone = PhoneNumberField(region="BD")
    address_type = models.CharField(
        max_length=120, choices=AddressType, default=AddressType.SHIPPING
    )
    country = CountryField(default="BD")
    city = models.CharField(max_length=255, default="Dhaka")
    street_address = models.CharField(max_length=255)
    area = models.CharField(max_length=255, null=True, blank=True)
    zip_code = models.CharField(max_length=15, null=True, blank=True)
    is_default = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name_plural = "User Addresses"
        verbose_name = "User Address"
        ordering = ["-created_at"]

    def __str__(self):
        return self.full_name
