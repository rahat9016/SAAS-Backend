from rest_framework.response import Response


def error_response(message: str, errors: dict = None, status_code: int = 400):
    return Response(
        {"success": False, "status_code": status_code, "message": message, "errors": errors},
        status=status_code,
    )


def success_response(message: str, data: dict = None, status_code: int = 200):
    return Response(
        {"success": True, "status_code": status_code, "message": message, "data": data},
        status=status_code,
    )
