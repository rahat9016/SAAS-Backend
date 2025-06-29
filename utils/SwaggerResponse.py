from rest_framework import serializers
from user.serializers import UserSerializer

class SuccessResponseSeralizer(serializers.Serializer):
    success = serializers.BooleanField(default=True)
    message = serializers.CharField()
    data = UserSerializer()


class ErrorResponseSeralizer(serializers.Serializer):
    success = serializers.BooleanField(default=False)
    message = serializers.CharField()
    errors = serializers.DictField(child=serializers.CharField(), required=False)
