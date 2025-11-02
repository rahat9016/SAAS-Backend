from rest_framework.exceptions import APIException
from rest_framework import status
from django.utils.translation import gettext as _

class AccountNotRegisteredException(APIException):
    status_code = status.HTTP_404_NOT_FOUND
    default_detail = ("The account is not registered.")
    default_code = "non-registered-account"
    

class AcountDisableException(APIException):
    status_code = status.HTTP_403_FORBIDDEN
    default_detail = _("User account is disabled.")
    default_code = "account-not-active"
    

class InvalidCredentialException(APIException):
    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = _("Wrong email or password")
    default_code = "invalid-credential"