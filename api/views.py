# api/views.py

from rest_framework import permissions, status, generics
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.exceptions import AuthenticationFailed
from .permissions import IsAdminUser
from .utils import generate_token, generate_refresh_token, JWTAuthentication
from giveaid.models import User, Cause, UserDonation, UnregisteredDonation, Payment, SuccessStory
from .serializers import (
    UserRegisterSerializer,
    CauseSerializer,
    UserSerializer,
    UnregisteredDonationSerializer,
    PaymentSerializer,
    SuccessStorySerializer
)
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import SessionAuthentication, BasicAuthentication
from giveaid_project import settings
import requests
import json  # Import the json module

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

'''
class DonationCreateView(APIView):
    def post(self, request):
        print("Posting...")
        user = request.user if request.user.is_authenticated else None
        serializer_class = UserDonationSerializer if user else UnregisteredDonationSerializer
        serializer = serializer_class(data=request.data)
        if serializer.is_valid():
            donation = serializer.save(user=user)
            # Integrate with Paystack here
            authorization_url = get_paystack_authorization_url(donation)
            print(authorization_url)
            send_donation_receipt.delay(donation.id)
            return Response({'status': 'success', 'authorization_url': authorization_url}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class DonationCreateView(APIView):
    # authentication_classes = [JWTAuthentication]
    # permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = UnregisteredDonationSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(status="pending")

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
                donation = Donation.objects.get(reference=serializer.data["reference"])
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
'''

class UserRegisterView(APIView):
    """
    A view for handling user registration.

    This view handles POST requests to register a new user. It uses a serializer 
    to validate and save the user data.

    Attributes:
        permission_classes (tuple): Specifies the permissions that apply to this view.
    """
    permission_classes = (permissions.AllowAny,)
    
    def post(self, request):
        serializer = UserRegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        
        return Response({
            "Message": "User Created Successfully"
        })
    

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

class CauseListView(generics.ListAPIView):
    queryset = Cause.objects.all()
    serializer_class = CauseSerializer
    permission_classes = (permissions.AllowAny,)

class UserView(APIView):
    pass

class PasswordReset(APIView):
    pass

class PasswordResetConfirm(APIView):
    pass
