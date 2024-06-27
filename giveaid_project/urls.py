from django.contrib import admin
from django.urls import path, include
from rest_framework.authtoken.views import obtain_auth_token
from api.views import UserRegistrationView, UserLoginView, UserLogoutView, \
    PasswordResetView, PasswordResetConfirmView, EmailVerificationView, \
    DonationCreateView, PaymentProcessView

urlpatterns = [
    path('admin/', admin.site.urls),

    # User Authentication URLs
    path('api/user/register/', UserRegistrationView.as_view(), name='user_register'),
    path('api/user/login/', obtain_auth_token, name='user_login'),
    path('api/user/logout/', UserLogoutView.as_view(), name='user_logout'),
    path('api/user/password/reset/', PasswordResetView.as_view(), name='password_reset'),
    path('api/user/password/reset/confirm/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('api/user/email/verify/', EmailVerificationView.as_view(), name='email_verify'),

    # Donation and Payment URLs
    path('api/donation/create/', DonationCreateView.as_view(), name='donation_create'),
    path('api/payment/process/', PaymentProcessView.as_view(), name='payment_process'),
]
