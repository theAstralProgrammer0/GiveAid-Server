from django.contrib import admin
from .models import Country, State, City, User, Cause, UserDonation, UnregisteredDonation, Payment, SuccessStory

# Register your models here.
admin.site.register(Country)
admin.site.register(State)
admin.site.register(City)
admin.site.register(User)
admin.site.register(Cause)
admin.site.register(UserDonation)
admin.site.register(UnregisteredDonation)
admin.site.register(Payment)
admin.site.register(SuccessStory)