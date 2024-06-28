from django.urls import path
from api.views import UserRegisterView, UserLoginView

urlpatterns = [
    path('user/register/', UserRegisterView.as_view(), name='user_register'),
    path('login/', UserLoginView.as_view(), name='user_login'),
    # path('/logout/', UserLogoutView.as_view(), name='user_logout'),
    # path('/user/password/reset/', PasswordResetView.as_view(), name='password_reset'),
    # path('/user/password/reset/confirm/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    # path('/user/email/verify/', EmailVerificationView.as_view(), name='email_verify'),
    # path(''),

    # Donation and Payment URLs
    # path('/donation/create/', DonationCreateView.as_view(), name='donation_create'),
    # path('/payment/process/', PaymentProcessView.as_view(), name='payment_process')
]