
from rest_framework.request import Request

def get_absolute_url(request: Request, relative_path: str) -> str | None:
    if not relative_path:
        return None
    return request.build_absolute_uri(relative_path)