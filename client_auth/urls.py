from django.urls import path
from .views import ClientAuthView, OTPVerificationView, ClientProfileView, GoogleSignInView

urlpatterns = [
    path('auth/', ClientAuthView.as_view(), name='client_auth'),
    path('auth/verify-phone/', OTPVerificationView.as_view(), name='otp_verification'),
    path('auth/complete-profile/', ClientProfileView.as_view(), name='client_profile'),
    path('auth/google/', GoogleSignInView.as_view(), name='google_signin'),
]