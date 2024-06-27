from rest_framework import serializers
from models import User, Cause, UserDonation, UnregisteredDonation, Payment, SuccessStory


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'firstname', 'middlename', 'lastname', 'dob', 'mobile', 'street', 'country', 'state', 'city']


class CauseSerializer(serializers.ModelSerializer):
    class Meta:
        model = Cause
        fields = '__all__'


class UserDonationSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserDonation
        fields = '__all__'


class UnregisteredDonationSerializer(serializers.ModelSerializer):
    class Meta:
        model = UnregisteredDonation
        fields = '__all__'


class PaymentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Payment
        fields = '__all__'


class SuccessStorySerializer(serializers.ModelSerializer):
    class Meta:
        model = SuccessStory
        fields = '__all__'
