from django.shortcuts import render
from rest_framework.generics import CreateAPIView
from rest_framework.permissions import AllowAny
from .serializers import RegisterSerializer, TokenSerializer
from .models import User
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.response import Response
from rest_framework  import status, serializers

# Create your views here.
class RegisterView(CreateAPIView):
    permission_classes = [AllowAny]
    queryset = User.objects.all()
    serializer_class = RegisterSerializer

class LoginView(TokenObtainPairView):
    serializer_class = TokenSerializer
    