from rest_framework import status
from rest_framework.response import Response
from typing import Optional, Any


class APIResponse:

    @staticmethod
    def _base(
        success: bool,
        message: str,
        data: Optional[Any] = None,
        errors: Optional[Any] = None,
        status_code: int = status.HTTP_200_OK,
    ) -> Response:
        """
        Base method for creating standardized responses.
        """
        response = {
            "status": status_code,
            "success": success,
            "message": message,
        }
        if success and data is not None:
            response["data"] = data

        if not success and errors is not None:
            response["errors"] = errors

        return Response(response, status=status_code)

    @classmethod
    def success(
        cls,
        message: str = "Operation success",
        data: Optional[Any] = None,
        status=status.HTTP_200_OK,
    ) -> Response:
        """Success response with optional data."""
        return cls._base(True, message, data, None, status)

    @classmethod
    def created(
        cls, message: str = "Resource created successfully", data: Optional[Any] = None
    ) -> Response:
        """201 Created response."""
        return cls._base(True, message, data, None, status.HTTP_201_CREATED)

    @classmethod
    def error(
        cls,
        message: str = "Something went wrong",
        data: Optional[Any] = None,
        errors: Optional[Any] = None,
        status=status.HTTP_400_BAD_REQUEST,
    ) -> Response:
        """Generic error response with optional data and errors."""
        return cls._base(False, message, data, errors, status)

    @classmethod
    def not_found(
        cls,
        message: str = "Resource not found",
        data: Optional[Any] = None,
    ) -> Response:
        return cls._base(
            False, message, data, None, status_code=status.HTTP_404_NOT_FOUND
        )

    @classmethod
    def unauthorized(
        cls, message: str = "Authentication required", data: Optional[Any] = None
    ):
        return cls._base(
            False, message, data, None, status_code=status.HTTP_401_UNAUTHORIZED
        )

    @classmethod
    def forbidden(
        cls, message: str = "Permission denied", data: Optional[Any] = None
    ) -> Response:
        return cls._base(
            False, message, data, None, status_code=status.HTTP_403_FORBIDDEN
        )

    @classmethod
    def validation_error(cls, errors, message: str = "Validation failed") -> Response:
        return cls._base(
            False, message, None, errors, status_code=status.HTTP_400_BAD_REQUEST
        )

    @classmethod
    def conflict(
        cls, message: str = "Resource already exists", data: Optional[Any] = None
    ) -> Response:
        """409 Conflict response."""
        return cls._base(False, message, data, None, status.HTTP_409_CONFLICT)

    @classmethod
    def server_error(
        cls, message: str = "Internal server error", data: Optional[Any] = None
    ) -> Response:
        """500 Internal Server Error response."""
        return cls._base(
            False, message, data, None, status.HTTP_500_INTERNAL_SERVER_ERROR
        )
