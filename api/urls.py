from django.urls import path
from rest_framework.authtoken.views import obtain_auth_token
from api.views import UserRegisterView, UserLoginView, ListUsersView, UserLogoutView, UserView, RefreshTokenView

urlpatterns = [
    path('user/register/', UserRegisterView.as_view(), name='user_register'),
    path('user/login/', UserLoginView.as_view(), name='user_login'),
    path('user/logout', UserLogoutView.as_view(), name='user logout'),
    path('user/', UserView.as_view(), name='user view'),
    path('users/list', ListUsersView.as_view(), name="list user"),
    path('user/refresh-token/', RefreshTokenView.as_view(), name='refresh-token'),
    # path('/user/password/reset/', PasswordResetView.as_view(), name='password_reset'),
    # path('/user/password/reset/confirm/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    # path('/user/email/verify/', EmailVerificationView.as_view(), name='email_verify'),

    # Donation and Payment URLs
    # path('/donation/create/', DonationCreateView.as_view(), name='donation_create'),
    # path('/payment/process/', PaymentProcessView.as_view(), name='payment_process')
]