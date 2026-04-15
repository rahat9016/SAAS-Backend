from django.core.exceptions import ObjectDoesNotExist
from rest_framework.exceptions import (
    AuthenticationFailed,
    MethodNotAllowed,
    NotFound,
    NotAuthenticated,
    PermissionDenied,
    ValidationError,
)
from rest_framework.views import exception_handler as drf_exception_handler
from core.utils.response import APIResponse


def custom_exception_handler(exc, context):
    # Known exception types → consistent APIResponse
    if isinstance(exc, (NotAuthenticated, AuthenticationFailed)):
        return APIResponse.unauthorized(str(exc))

    if isinstance(exc, (NotFound, ObjectDoesNotExist)):
        return APIResponse.not_found(str(exc))

    if isinstance(exc, PermissionDenied):
        return APIResponse.forbidden(str(exc))

    if isinstance(exc, ValidationError):
        drf_response = drf_exception_handler(exc, context)
        return APIResponse.error(
            message="Validation error",
            errors=drf_response.data,
            status=drf_response.status_code,
        )

    if isinstance(exc, MethodNotAllowed):
        return APIResponse.error(message="Method not allowed", status=405)

    drf_response = drf_exception_handler(exc, context)

    if drf_response is not None:
        # Wrap DRF's response into our APIResponse shape
        return APIResponse.error(
            message=drf_response.data.get('detail', 'An error occurred'),
            errors=drf_response.data,
            status=drf_response.status_code,
        )
    return APIResponse.error(
        message="Internal server error",
        status=500,
    )