import uuid
from django.db import models
from django.contrib.auth.models import AbstractUser

# Create your models here.
class Country(models.Model):
    id = models.BigAutoField(primary_key=True, verbose_name="country id")
    name = models.CharField(max_length=255, verbose_name="country name")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.name
    
    class Meta:
        db_table = "country"


class State(models.Model):
    id = models.BigAutoField(primary_key=True, verbose_name="state id")
    country = models.ForeignKey(Country, on_delete=models.CASCADE, verbose_name="country city is in")
    name = models.CharField(max_length=255, verbose_name="state name")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.name
    
    class Meta:
        db_table = "state"


class City(models.Model):
    id = models.BigAutoField(primary_key=True, verbose_name="city id")
    state = models.ForeignKey(State, on_delete=models.CASCADE, verbose_name="state city is in")
    name = models.CharField(max_length=255, verbose_name="city name")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.name
    
    class Meta:
        db_table = "city"


class User(AbstractUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, verbose_name="user id")
    country = models.ForeignKey(Country, on_delete=models.CASCADE)
    state = models.ForeignKey(State, on_delete=models.CASCADE)
    city = models.ForeignKey(City, on_delete=models.CASCADE)
    username = models.CharField(max_length=255, unique=True)
    firstname = models.CharField(max_length=255)
    middlename = models.CharField(max_length=255, null=True, blank=True)
    lastname = models.CharField(max_length=255)
    email = models.EmailField(max_length=254, unique=True)
    password = models.CharField(max_length=255)
    dob = models.DateField()
    mobile = models.CharField(max_length=255, null=True, blank=True)
    street = models.CharField(max_length=255, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        self.username
        
    class Meta:
        db_table = "user"
  
        
class Cause(models.Model):
    id = models.BigAutoField(primary_key=True, verbose_name="cause id")
    title = models.CharField(max_length=255,verbose_name="cause title")
    description = models.TextField(verbose_name="cause description")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.title
    
    class Meta:
        db_table = "cause"
    

class UserDonation(models.Model):
    id = models.BigAutoField(primary_key=True, verbose_name="user donation id")
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    cause = models.ForeignKey(Cause, on_delete=models.CASCADE)
    description = models.TextField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"Donation by {self.user.username} to {self.cause.title}"
    
    class Meta:
        db_table = "userdonation"   
 

class UnregisteredDonation(models.Model):
    id = models.BigAutoField(primary_key=True, verbose_name="Unregistered donation id")
    cause = models.ForeignKey(Cause, on_delete=models.CASCADE)
    firstname = models.CharField(max_length=255)
    lastname = models.CharField(max_length=255)
    email = models.EmailField(max_length=254)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"Unregistered donor donation to {self.cause.title}"
    
    class Meta:
        db_table = "unregistereddonation"


class Payment(models.Model):
    DONATION_TYPE_CHOICES = [
		('user', 'User Donation'),
		('unregistered', 'Unregistered Donation')
	]
    
    id = models.BigAutoField(primary_key=True, verbose_name="Payment id")
    donation_type = models.CharField(max_length=13, choices=DONATION_TYPE_CHOICES)
    donation_id = models.PositiveBigIntegerField()
    transaction_id = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    payment_method = models.CharField(max_length=255)
    payment_date = models.DateField(auto_now_add=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"Payment of: {self.amount}. \tTransaction ID: {self.transaction_id}"
    
    def get_donation(self):
        if self.donation_type == 'user':
            return UserDonation.objects.get(id=self.donation_id)
        elif self.donation_type == 'unregistered':
            return UnregisteredDonation.objects.get(id=self.donation_id)
        return None
    
    class Meta:
        db_table = "payment"


class SuccessStory(models.Model):
    id = models.BigAutoField(primary_key=True, verbose_name="Success story id")
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    cause = models.ForeignKey(Cause, on_delete=models.CASCADE)
    title = models.CharField(max_length=255)
    description = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.title
    
    class Meta:
        db_table = "successstory"