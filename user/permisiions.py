from rest_framework.permissions import BasePermission

class IsAdminOrSelf(BasePermission):
    def has_object_permission(self, request, view, obj):
        user = request.user
        if not user or not user.is_authenticated:
            return False
        if user.is_staff:
            return True
        else:
            return obj.id == user.id