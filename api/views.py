from rest_framework import permissions, status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.exceptions import AuthenticationFailed
from giveaid.models import User, Cause, UserDonation, UnregisteredDonation, Payment, SuccessStory
from .serializers import (
    UserRegisterSerializer,
    CauseSerializer,
    UserDonationSerializer,
    UnregisteredDonationSerializer,
    PaymentSerializer,
    SuccessStorySerializer,
)


class UserRegisterView(APIView):
    permission_classes = (permissions.AllowAny,)
    
    def post(self, request):
        serializer = UserRegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)
    
    
class UserLoginView(APIView):
    def post(self, request):
        email = request.data['email']
        password = request.data['password']
        
        user = User.objects.filter(email=email).first()
        if user is None:
            raise AuthenticationFailed('User Not Found')
        
        if not user.check_password(password):
            raise AuthenticationFailed('Incorrect Password')
        
        return Response({
            'message': 'User Logged in successfully'
        })