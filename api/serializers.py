from rest_framework import serializers
from rest_framework.response import Response
from giveaid.models import User, Cause, UserDonation, UnregisteredDonation, Payment, SuccessStory

class UserRegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User 
        fields = ['id', 'username', 'email', 'firstname', 'lastname', 'password']
        extra_args = {
            'password': {'write_only': True}
        }
        
    def create(self, validated_data):
        password = validated_data.get('password', None)
        instance = self.Meta.model(**validated_data)
        if password is not None:
            instance.set_password(password)
        instance.save()
        
        return Response(instance)
    

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'firstname', 'middlename', 'lastname', 'dob', 'mobile', 'country', 'state', 'city', 'street']


class CauseSerializer(serializers.ModelSerializer):
    class Meta:
        model = Cause
        fields = '__all__'


class UserDonationSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserDonation
        fields = '__all__'


class UnregisteredDonationSerializer(serializers.ModelSerializer):
    cause = serializers.PrimaryKeyRelatedField(queryset=Cause.objects.all(), required=True)
    
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
