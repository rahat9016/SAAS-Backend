from rest_framework.views import exception_handler
from rest_framework.response import Response
from rest_framework import status
import logging
def custom_exception_handler(exc, context):
    response = exception_handler(exc, context)
    
    if response is not None:
        return Response(
            {
                "success": False,
                "message": "Validation error" if response.status_code == 400 else "Request failed",
                "errors": response.data
            },
            status=response.status_code
        )
    
    logger = logging.getLogger(__name__)
    logger.exception(f"Unhandled server error: {exc}")
    return Response(
        {
            "success": False,
            "message": "Server error",
            "errors": {}
        },
        status=status.HTTP_500_INTERNAL_SERVER_ERROR
    )