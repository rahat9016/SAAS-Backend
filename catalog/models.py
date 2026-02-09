from django.db import models
import uuid


class Category(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255, unique=True)
    description = models.TextField(blank=True, null=True)
    icon = models.ImageField(
        upload_to="category/icons/", blank=True, null=True
    )

    class Meta:
        db_table = "categories"
        ordering = ["name"]

    def __str__(self):
        return self.name


class SubCategory(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255, unique=True)
    parent_category = models.ForeignKey(
        Category,
        on_delete=models.SET_NULL,
        related_name="subcategories",
        null=True,
        blank=True,
    )
    description = models.TextField(blank=True, null=True)
    icon = models.ImageField(
        upload_to="subcategory/icons/", blank=True, null=True
    )

    class Meta:
        db_table = "sub_categories"
        unique_together = ("parent_category", "name")
        ordering = ["name"]

    def __str__(self):
        return self.name


class Brand(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255, unique=True)
    description = models.TextField(blank=True, null=True)
    icon = models.ImageField(upload_to="Brand/icons/")

    class Meta:
        db_table = "Brand"
        ordering = ["name"]

    def __str__(self):
        return self.name