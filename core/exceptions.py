from rest_framework.views import exception_handler
from rest_framework.response import Response
from rest_framework import status

import logging
from django.conf import settings


def custom_exception_handler(exc, context):
    """
    Custom exception handler for consistent API responses
    """
    response = exception_handler(exc, context)
    request = context.get("request")

    if response is not None:
        error_mapping = {
            400: ("Validation error", "validation_error"),
            401: ("Authentication required", "authentication_error"),
            403: ("Permission denied", "authorization_error"),
            404: ("Resource not found", "not_found_error"),
            405: ("Method not allowed", "method_error"),
            429: ("Too many requests", "rate_limit_error"),
        }

        message, error_type = error_mapping.get(
            response.status_code, ("Request failed", "client_error")
        )

        # Format validation errors consistently
        formatted_errors = format_validation_errors(response.data)
        print("Formatted Errors->", formatted_errors)
        return Response(
            {
                "success": False,
                "message": message,
                "status_code": response.status_code,
                "errors": formatted_errors,
            },
            status=response.status_code,
        )

    # Log unhandled exceptions
    logging.error(
        f"Unhandled exception in {context.get('view', 'unknown')}: {str(exc)}",
        extra={"request": request},
        exc_info=True,
    )

    # Return safe error response
    return Response(
        {
            "success": False,
            "message": "Internal server error" if not settings.DEBUG else str(exc),
            "status_code": 500,
            "errors": {"error": "Please try again later"},
        },
        status=500,
    )


def format_validation_errors(errors):
    """Flatten DRF validation errors into a simple dict without non_field_errors"""
    if isinstance(errors, dict):
        if "non_field_errors" in errors and len(errors) == 1:
            return {"error": errors["non_field_errors"]}
        return {
            key: value if isinstance(value, list) else [str(value)]
            for key, value in errors.items()
            if key != "non_field_errors"
        }

    # For string / non-dict cases
    return {"error": [str(errors)]}
