from django.conf import settings
from datetime import datetime, timezone, timedelta
import jwt
import requests
from django.contrib.auth.models import User
from django.contrib.auth import get_user_model
from rest_framework import authentication, exceptions


User = get_user_model()

def generate_token(user):
    """
    Generate a JSON Web Token for a given user.

    Args:
    user (User): The user object for whom the token is being generated.

    Returns:
    str: The generated JWT.
    """
    user_id = str(user.id)
    payload = {
        "user_id": user_id,
        "exp": datetime.now(timezone.utc) + timedelta(hours=2),
        'iat': datetime.now(timezone.utc),
        'token_type': 'access'
	}
    
    access_token = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")
    return access_token


def generate_refresh_token(user):
    """
    Generate a refresh token for a given user.

    This function creates a JWT (JSON Web Token) that includes the user's ID, 
    an expiration date set to 7 days from the token's creation, and an issued-at timestamp.

    Args:
        user (User): The user object for whom the refresh token is being generated. 
        The user object must have an 'id' attribute.

    Returns:
        str: The generated JWT as a string.
    """
    user_id = str(user.id)
    payload = {
        "user_id": user_id,
        "exp": datetime.now(timezone.utc) + timedelta(days=7),
        'iat': datetime.now(timezone.utc),
        'token_type': 'refresh'
	}
    
    refresh_token = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")
    return refresh_token



class JWTAuthentication(authentication.BaseAuthentication):
    """
    Custom authentication class for validating JWT tokens.

    This class provides methods to authenticate requests using JWT tokens. It checks 
    the Authorization header for a Bearer token, decodes the token, and retrieves 
    the associated user.

    Methods:
        authenticate(request): Extracts the token from the request and validates it.
        _authenticate_credentials(token): Decodes the token and retrieves the user.
    """
    def authenticate(self, request):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return None

        try:
            prefix, token = auth_header.split(' ')
            if prefix.lower() != 'bearer':
                raise exceptions.AuthenticationFailed('Invalid token prefix')
        except ValueError:
            raise exceptions.AuthenticationFailed('Invalid token header')

        return self._authenticate_credentials(token)


    def _authenticate_credentials(self, token):
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            if payload.get('token_type') != 'access':
                raise exceptions.AuthenticationFailed('Invalid token type')
        except jwt.ExpiredSignatureError:
            raise exceptions.AuthenticationFailed('Token has expired')
        except jwt.InvalidTokenError:
            raise exceptions.AuthenticationFailed('Invalid token')

        try:
            user = User.objects.get(id=payload['user_id'])
        except User.DoesNotExist:
            raise exceptions.AuthenticationFailed('User not found')

        return (user, token)
    
    
    @staticmethod
    def decode_refresh_token(token):
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            if payload.get('token_type') != 'refresh':
                raise exceptions.AuthenticationFailed('Invalid token type')
            return payload['user_id']
        except jwt.ExpiredSignatureError:
            raise exceptions.AuthenticationFailed("Refresh token has expired")
        except jwt.InvalidTokenError:
            raise exceptions.AuthenticationFailed('Invalid Refresh Token')
            


def get_paystack_authorization_url(donation):
    print("I just go into the get paystack auth url")
    url = 'https://api.paystack.co/transaction/initialize'
    headers = {
        'Authorization': f'Bearer {PAYSTACK_SECRET_KEY}',
        'Content-Type': 'application/json'
    }
    data = {
        'email': donation.email,
        'amount': int(donation.amount) * 100,  # Paystack amount is in kobo
        'callback_url': 'http://127.0.0.1:3000'
    }
    response = requests.post(url, headers=headers, json=data)
    return response.json().get('data').get('authorization_url')

