from rest_framework.views import exception_handler
from core.utils.response import APIResponse
from rest_framework import status

def custom_exception_handler(exc, context):
    """
    Wrap DRF exceptions in your APIResponse format
    """
    response = exception_handler(exc, context)

    if response is not None:
        # DRF ValidationError
        if response.status_code == status.HTTP_400_BAD_REQUEST:
            return APIResponse.validation_error(errors=response.data)
        # Not found
        elif response.status_code == status.HTTP_404_NOT_FOUND:
            return APIResponse.not_found()
        # Unauthorized
        elif response.status_code == status.HTTP_401_UNAUTHORIZED:
            return APIResponse.unauthorized()
        # Forbidden
        elif response.status_code == status.HTTP_403_FORBIDDEN:
            return APIResponse.forbidden()
        # Conflict (optional)
        elif response.status_code == status.HTTP_409_CONFLICT:
            return APIResponse.conflict(data=response.data)
        # Other errors
        else:
            return APIResponse.error(
                message=str(response.data),
                data=None,
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    # Non-DRF exception (500)
    return APIResponse.server_error(message=str(exc))
