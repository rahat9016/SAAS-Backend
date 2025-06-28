from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.utils.translation import gettext_lazy as _
from django.contrib.auth import get_user_model

# from .models import User
User = get_user_model()
class UserSerializer(serializers.ModelSerializer):
    username = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = ('id','first_name', 'last_name', 'email', 'phone', 'profile_picture', 'role', 'created_at', 'username')
        
    def get_username(self, obj):
        return obj.username
