# client_auth/views.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import ClientSignupSerializer, OTPSerializer, ClientProfileSerializer, GoogleSignInSerializer
from .models import CustomUser
from .utils import OTPHandler, WhatsAppService
import logging
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from django.conf import settings

logger = logging.getLogger(__name__)

class ClientAuthView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        logger.debug(f"Received request data: {request.data}")
        phone_number = request.data.get('phone_number')
        if not phone_number:
            logger.warning("Phone number missing in request")
            return Response({'error': 'Phone number required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Check if user already exists
            user = CustomUser.objects.get(phone_number=phone_number)
            is_new_user = False
            logger.info(f"Existing user found: {phone_number}")
        except CustomUser.DoesNotExist:
            try:
                # Create a new user using the CustomUserManager
                user = CustomUser.objects.create_user(phone_number=phone_number)
                is_new_user = True
                logger.info(f"New user created: {phone_number}")
            except ValueError as e:
                logger.error(f"Failed to create user for {phone_number}: {str(e)}")
                return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

        # Generate and store OTP
        otp = OTPHandler.generate_otp()
        OTPHandler.store_otp(phone_number, otp)

        # Send OTP via WhatsApp
        if WhatsAppService.send_otp(phone_number, user.first_name or "Client", otp):
            logger.info(f"OTP sent to {phone_number}")
            return Response({
                'message': 'OTP sent',
                'phone_number': phone_number,
                'is_new_user': is_new_user
            }, status=status.HTTP_200_OK if is_new_user else status.HTTP_201_CREATED)

        # If OTP sending fails, delete the user if it was newly created
        if is_new_user:
            user.delete()
            logger.info(f"Deleted newly created user {phone_number} due to OTP sending failure")
        logger.error(f"Failed to send OTP for {phone_number}")
        return Response({'error': 'Failed to send OTP'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class OTPVerificationView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = OTPSerializer(data=request.data)
        if not serializer.is_valid():
            logger.error(f"OTP validation failed: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        phone_number = serializer.validated_data['phone_number']
        otp = serializer.validated_data.get('otp')

        try:
            user = CustomUser.objects.get(phone_number=phone_number)
        except CustomUser.DoesNotExist:
            logger.error(f"User not found for {phone_number}")
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        if otp:
            # Verify OTP
            if OTPHandler.verify_otp(phone_number, otp):
                user.is_verified = True
                user.save()
                OTPHandler.clear_otp(phone_number)
                refresh = RefreshToken.for_user(user)
                logger.info(f"User {phone_number} verified successfully")
                return Response({
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                    'user': ClientProfileSerializer(user).data,
                    'is_new_user': not user.first_name
                }, status=status.HTTP_200_OK)
            logger.error(f"Invalid OTP for {phone_number}")
            return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            # Resend OTP if no OTP is provided
            otp = OTPHandler.generate_otp()
            OTPHandler.store_otp(phone_number, otp)
            if WhatsAppService.send_otp(phone_number, user.first_name or "Client", otp):
                logger.info(f"New OTP sent to {phone_number}")
                return Response({
                    'message': 'OTP sent',
                    'phone_number': phone_number
                }, status=status.HTTP_200_OK)
            logger.error(f"Failed to send OTP to {phone_number}")
            return Response({'error': 'Failed to send OTP'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ClientProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        serializer = ClientProfileSerializer(request.user)
        logger.info(f"Profile retrieved for {request.user.phone_number}")
        return Response(serializer.data)

    def patch(self, request):
        serializer = ClientProfileSerializer(request.user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            logger.info(f"Profile updated for {request.user.phone_number}")
            return Response(serializer.data)
        logger.error(f"Profile update failed for {request.user.phone_number}: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class GoogleSignInView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        logger.debug(f"Received Google Sign-In request: {request.data}")
        serializer = GoogleSignInSerializer(data=request.data)
        if not serializer.is_valid():
            logger.error(f"Google Sign-In validation failed: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        id_token_str = serializer.validated_data['access_token']
        phone_number = serializer.validated_data.get('phone_number')

        try:
            logger.debug(f"Verifying Google token: {id_token_str[:10]}...")
            idinfo = id_token.verify_oauth2_token(id_token_str, google_requests.Request(), settings.GOOGLE_CLIENT_ID)
            logger.debug(f"Token verified: {idinfo}")
            google_id = idinfo['sub']
            email = idinfo['email']
            first_name = idinfo.get('given_name', '')
            last_name = idinfo.get('family_name', '')

            # Look for an existing user by google_id or email
            user = CustomUser.objects.filter(google_id=google_id).first() or CustomUser.objects.filter(email=email).first()

            if not user:
                # New user: Create temporarily and require phone number later
                user = CustomUser.objects.create(
                    google_id=google_id,
                    email=email,
                    first_name=first_name,
                    last_name=last_name
                )
                logger.info(f"New Google user created: {email}. Redirecting for phone entry.")
                return Response({
                    'message': 'New user, phone number required',
                    'is_new_user': True,
                    'user': ClientProfileSerializer(user).data,
                    'google_id': google_id
                }, status=status.HTTP_201_CREATED)
            elif phone_number:
                # Phone number provided (e.g., from UserSignupScreen)
                user.phone_number = phone_number
                user.save()
                otp = OTPHandler.generate_otp()
                OTPHandler.store_otp(phone_number, otp)
                if WhatsAppService.send_otp(phone_number, first_name or "Client", otp):
                    logger.info(f"OTP sent to {phone_number} for Google user {email}")
                    return Response({
                        'message': 'OTP sent for phone verification',
                        'phone_number': phone_number,
                        'is_new_user': False,
                        'google_id': google_id
                    }, status=status.HTTP_200_OK)
                user.delete()
                logger.error(f"Failed to send OTP to {phone_number}")
                return Response({'error': 'Failed to send OTP'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            elif user.is_verified:
                # Existing verified user
                refresh = RefreshToken.for_user(user)
                logger.info(f"Google Sign-In successful for verified user {user.phone_number or user.email}")
                return Response({
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                    'user': ClientProfileSerializer(user).data,
                    'is_new_user': False
                }, status=status.HTTP_200_OK)
            else:
                # Existing user without phone number or verification
                logger.info(f"Existing Google user {email} needs phone verification.")
                return Response({
                    'message': 'Phone number required for verification',
                    'is_new_user': False,
                    'user': ClientProfileSerializer(user).data,
                    'google_id': google_id
                }, status=status.HTTP_200_OK)

        except ValueError as e:
            logger.error(f"Invalid Google token: {str(e)}")
            return Response({'error': f'Invalid Google token: {str(e)}'}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            logger.error(f"Google Sign-In error: {str(e)}")
            return Response({'error': 'Authentication failed'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)