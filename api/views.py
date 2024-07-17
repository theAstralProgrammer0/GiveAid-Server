# api/views.py

import requests
import json
from rest_framework import permissions, status, generics
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import SessionAuthentication, BasicAuthentication
from django.contrib.auth.tokens import default_token_generator
from giveaid_project import settings
from giveaid.models import User, Cause, UserDonation, UnregisteredDonation, Payment, SuccessStory
from .permissions import IsAdminUser
from .utils import generate_token, generate_refresh_token, JWTAuthentication, send_reset_email
from .serializers import (
    UserSerializer,
    UserRegisterSerializer,
    CauseSerializer,
    UserSerializer,
    UnregisteredDonationSerializer,
    PaymentSerializer,
    SuccessStorySerializer
)

class DonationCreateView(APIView):
    permission_classes = (permissions.AllowAny,)

    def post(self, request):
        serializer = UnregisteredDonationSerializer(data=request.data)
        if serializer.is_valid():
            donation = serializer.save(status="pending")

            # Create Paystack Transaction
            url = "https://api.paystack.co/transaction/initialize"
            headers = {
                'Authorization': f'Bearer {settings.PAYSTACK_SECRET_KEY}',
                'Content-Type': 'application/json'
            }
            data = {
                'email': request.data['email'],
                'amount': int(float(request.data["amount"]) * 100),
                'metadata': {
                    "custom_fields": [
                        {"display_name": "Name", "variable_name": "name", "value": request.data["name"]},
                        {"display_name": "Cause", "variable_name": "cause", "value": request.data["cause"]}
                    ]
                }
            }
            response = requests.post(url, headers=headers, data=json.dumps(data))
            paystack_response = response.json()

            if paystack_response["status"]:
                donation.status = "pending"
                donation.save()
                return Response({
                    "status": True,
                    "message": "Authorization URL created",
                    "data": paystack_response["data"]
                })
            else:
                return Response({"status": False, "message": "Payment initialization failed"}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserDonationCreateView(APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request):
        serializer = UserDonationSerializer(data=request.data)
        if serializer.is_valid():
            donation = serializer.save(user=request.user, status="pending")

            # Create Paystack Transaction
            url = "https://api.paystack.co/transaction/initialize"
            headers = {
                'Authorization': f'Bearer {settings.PAYSTACK_SECRET_KEY}',
                'Content-Type': 'application/json'
            }
            data = {
                'email': request.user.email,
                'amount': int(float(request.data["amount"]) * 100),
                'metadata': {
                    "custom_fields": [
                        {"display_name": "Name", "variable_name": "name", "value": request.user.username},
                        {"display_name": "Cause", "variable_name": "cause", "value": donation.cause.title}
                    ]
                }
            }
            response = requests.post(url, headers=headers, data=json.dumps(data))
            paystack_response = response.json()

            if paystack_response["status"]:
                donation.status = "pending"
                donation.save()
                return Response({
                    "status": True,
                    "message": "Authorization URL created",
                    "data": paystack_response["data"]
                })
            else:
                return Response({"status": False, "message": "Payment initialization failed"}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserRegisterView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class UserLoginView(APIView):
    """
    A view for handling user login and authentication.

    This view handles POST requests to authenticate a user based on email and password.
    If authentication is successful, it generates access and refresh tokens, sets an 
    HTTP-only cookie for the access token, and returns the tokens in the response.

    Attributes:
        permission_classes (tuple): Specifies the permissions that apply to this view.
    """
    permission_classes = (permissions.AllowAny,)
    
    def post(self, request):
        print("Logging in")
        email = request.data['email']
        password = request.data['password']
        
        user = User.objects.filter(email=email).first()
        if user is None:
            raise AuthenticationFailed('User Not Found')
        
        if not user.check_password(password):
            raise AuthenticationFailed('Incorrect Password')
        
        if user.is_active:
            user_access_token = generate_token(user)
            refresh_token = generate_refresh_token(user)
            response = Response()
            response.set_cookie(key='access_token', value=user_access_token, httponly=True)
            response.data = {
                'access_token': user_access_token,
                'refresh_token': refresh_token
            }
            return response
        
        return Response({
            'message': 'Uh Uh! Something went wrong'
        }, status=status.HTTP_400_BAD_REQUEST)


class ListUsersView(APIView):
    """
    A view for listing all users.

    This view allows only admin users to retrieve a list of all users registered 
    in the system. It uses JWT authentication to verify the user's identity.

    Attributes:
        authentication_classes (list): Specifies the authentication classes used for this view.
        permission_classes (tuple): Specifies the permissions that apply to this view.
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = (IsAdminUser,)
    
    def get(self, request):
        users = User.objects.all()
        if not users.exists():
            return Response({
                "detail": "No users found"
            }, status=status.HTTP_404_NOT_FOUND)
        
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    

class RefreshTokenView(APIView):
    """
    A view for refreshing access tokens using a refresh token.

    This view handles POST requests to refresh an access token using a provided 
    refresh token. It decodes the refresh token to retrieve the user ID, generates 
    a new access token and refresh token pair, and returns them in the response.

    Methods:
        post(request): Handles POST requests to refresh tokens.
    """
    def post(self, request):
        refresh_token = request.data.get('refresh_token')
        if refresh_token is None:
            raise AuthenticationFailed('Refresh token is required')
        
        user_id = JWTAuthentication.decode_refresh_token(refresh_token)
        user = User.objects.filter(id=user_id).first()
        if user is None:
            raise AuthenticationFailed('User not found')
        
        access_token = generate_token(user)
        new_refresh_token = generate_refresh_token(user)
        response_data = {
            'access-token': access_token,
            'refresh_token': new_refresh_token
        }
        
        return Response(response_data)


class UserLogoutView(APIView):
    """
    A view for handling user logout.

    This view allows users to log out by deleting the access token cookie. 
    It does not require authentication to access this endpoint.

    Attributes:
        authentication_classes (list): Specifies the authentication classes used for this view.
        permission_classes (tuple): Specifies the permissions that apply to this view.
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = (permissions.AllowAny,)
    
    def get(self, request):
        user_token = request.COOKIES.get('access_token', None)
        if user_token:
            response = Response()
            response.delete_cookie('access_token')
            response.data = {
                'message': 'Logged Out Successfully'
            }
            return response
        
        response = Response()
        response.data = {
            'message': 'User is already logged out'
        }
        return response


class UserView(APIView):
    pass

class CauseListView(generics.ListAPIView):
    queryset = Cause.objects.all()
    serializer_class = CauseSerializer
    permission_classes = (permissions.AllowAny,)


class SuccessStoryListView(generics.ListAPIView):
    queryset = SuccessStory.objects.all()
    serializer_class = SuccessStorySerializer
    permission_classes = (permissions.AllowAny,)


class ForgotPasswordView(APIView):
    def post(self, request):
        email = request.data.get('email')
        try:
            user = User.objects.get(email=email)
            token = default_token_generator.make_token(user)
            send_reset_email(user, token)
            return Response({'status': 'success', 'message': 'Password reset email sent.'}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({'status': 'failed', 'message': 'User with this email does not exist.'}, status=status.HTTP_404_NOT_FOUND)

class ResetPasswordView(APIView):
    def post(self, request):
        token = request.data.get('token')
        password = request.data.get('password')
        try:
            user = User.objects.get(pk=request.data.get('user_id'))
            if default_token_generator.check_token(user, token):
                user.set_password(password)
                user.save()
                return Response({'status': 'success', 'message': 'Password reset successfully.'}, status=status.HTTP_200_OK)
            else:
                return Response({'status': 'failed', 'message': 'Invalid token.'}, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            return Response({'status': 'failed', 'message': 'User does not exist.'}, status=status.HTTP_404_NOT_FOUND)
