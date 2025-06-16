from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.utils.translation import gettext_lazy as _
from django.contrib.auth import authenticate
from .models import User
import re

class UserSerializer(serializers.ModelSerializer):
    username = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = ('id','first_name', 'last_name', 'email', 'phone', 'profile_picture', 'role', 'created_at')
        extra_kwargs = {
            'password': {'write_only': True} 
        }
        
    def get_username(self, obj):
        return obj.username


class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('first_name', 'last_name', 'email', 'phone', 'password')
        extra_kwargs = {
            'password': {'write_only': True} 
        }
    
    def create(self, validated_data):
        user = User.objects.create(**validated_data)
        return user
    

class TokenSerializer(TokenObtainPairSerializer):
    phone = serializers.CharField(write_only=True)
    password = serializers.CharField(
        style = {'input_type': 'password'},
        trim_whitespace=False,
        write_only=True
    )
    
    default_error_messages = {
        'no_active_account': _('Invalid phone number or password'),
        'invalid_phone': _('Please provide a valid phone number')
    }
    
    def validate(self, attrs):
        phone = attrs.get('phone')
        password = attrs.get('password')
        
        if not phone:
            raise serializers.ValidationError(
                {'phone': _('Phone number is required')}
            )
        if not re.match(r'^\+?[0-9\s\-\(\)]{7,20}$', phone):
            raise serializers.ValidationError(
                self.error_messages['invalid_phone']
            )
        
        user = authenticate(request=self.context.get('request'), phone=phone, password=password)
        if not user:
            raise serializers.ValidationError(
                self.error_messages['no_active_account']
            )
            
        # If user number not active then raise the error.
        if not user.is_active:
            raise serializers.ValidationError(_('User account is disabled'))
        
    
        refresh = self.get_token(user)
        
        data = {
            'access': str(refresh.access_token),
            'refresh': str(refresh),
            'role': user.role,
        }
        return data
         
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['role'] = user.role
        return token

