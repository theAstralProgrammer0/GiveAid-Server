from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.decorators import api_view
from django.contrib.auth import get_user_model
from django.shortcuts import get_object_or_404
from .models import Cause, UserDonation, UnregisteredDonation, Payment, SuccessStory
from .serializers import (
    UserSerializer,
    CauseSerializer,
    UserDonationSerializer,
    UnregisteredDonationSerializer,
    PaymentSerializer,
    SuccessStorySerializer,
)
from .permissions import IsOwnerOrReadOnly

User = get_user_model()

# User Registration View
class UserCreateAPIView(generics.CreateAPIView):
    """
    API endpoint for user registration.
    """
    queryset = User.objects.all()
    serializer_class = UserSerializer
    # Non authenticated users are allowed to register
    permission_classes = [permissions.AllowAny]

# User Profile View
class UserProfileAPIView(generics.RetrieveUpdateAPIView):
    """
    API endpoint to retrieve or update user profile details.
    """
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        # Retrieves the current authenticated user's profile
        return self.request.user

# Cause List and Detail Views
class CauseListAPIView(generics.ListAPIView):
    """
    API endpoint to list all causes.
    """
    queryset = Cause.objects.all()
    serializer_class = CauseSerializer
    permission_classes = [permissions.AllowAny]

class CauseDetailAPIView(generics.RetrieveAPIView):
    """
    API endpoint to retrieve details of a specific cause.
    """
    queryset = Cause.objects.all()
    serializer_class = CauseSerializer
    # Any user has permission to view cause details 
    permission_classes = [permissions.AllowAny]

# User Donation Views
class UserDonationCreateAPIView(generics.CreateAPIView):
    """
    API endpoint to create a user donation.
    """
    queryset = UserDonation.objects.all()
    serializer_class = UserDonationSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

class UserDonationListAPIView(generics.ListAPIView):
    """
    API endpoint to list user's donations.
    """
    queryset = UserDonation.objects.all()
    serializer_class = UserDonationSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return self.queryset.filter(user=self.request.user)

# Unregistered Donation View
class UnregisteredDonationCreateAPIView(generics.CreateAPIView):
    """
    API endpoint to create an unregistered donation.
    """
    queryset = UnregisteredDonation.objects.all()
    serializer_class = UnregisteredDonationSerializer
    permission_classes = [permissions.AllowAny]

# Payment View
class PaymentCreateAPIView(generics.CreateAPIView):
    """
    API endpoint to process a payment.
    """
    queryset = Payment.objects.all()
    serializer_class = PaymentSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

# Success Story Views
class SuccessStoryListAPIView(generics.ListAPIView):
    """
    API endpoint to list all success stories.
    """
    queryset = SuccessStory.objects.all()
    serializer_class = SuccessStorySerializer
    # Any user has permission to view success stories
    permission_classes = [permissions.AllowAny]

class SuccessStoryCreateAPIView(generics.CreateAPIView):
    """
    API endpoint to create a success story.
    """
    queryset = SuccessStory.objects.all()
    serializer_class = SuccessStorySerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)
