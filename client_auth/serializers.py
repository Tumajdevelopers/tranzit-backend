from rest_framework import serializers
from .models import CustomUser

class ClientSignupSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['phone_number', 'first_name', 'last_name', 'email']
    
    def validate_phone_number(self, value):
        if CustomUser.objects.filter(phone_number=value).exists():
            raise serializers.ValidationError("This phone number is already registered.")
        return value

class OTPSerializer(serializers.Serializer):
    phone_number = serializers.CharField(max_length=17)
    otp = serializers.CharField(max_length=6, required=False)

class ClientProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['phone_number', 'first_name', 'last_name', 'email', 'is_verified']

class GoogleSignInSerializer(serializers.Serializer):
    access_token = serializers.CharField()  # Kept as 'access_token' to match frontend payload
    phone_number = serializers.CharField(max_length=17, required=False)