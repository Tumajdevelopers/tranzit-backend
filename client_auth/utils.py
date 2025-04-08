import pyotp
import requests
from django.core.cache import cache
import logging

logger = logging.getLogger(__name__)
WHATSAPP_API_URL = 'http://195.179.229.205:3000/client/sendMessage/f8377d8d-a589-4242-9ba6-9486a04ef80c'

class OTPHandler:
    @staticmethod
    def generate_otp():
        return pyotp.TOTP(pyotp.random_base32(), interval=300).now()

    @staticmethod
    def store_otp(phone_number, otp):
        cache_key = f"otp_{phone_number}"
        cache.set(cache_key, otp, timeout=300)
        return cache_key

    @staticmethod
    def verify_otp(phone_number, submitted_otp):
        cache_key = f"otp_{phone_number}"
        stored_otp = cache.get(cache_key)
        return stored_otp and str(submitted_otp) == str(stored_otp)

    @staticmethod
    def clear_otp(phone_number):
        cache_key = f"otp_{phone_number}"
        cache.delete(cache_key)

class WhatsAppService:
    @staticmethod
    def send_otp(phone_number, name, otp):
        try:
            formatted_number = str(phone_number).replace('+', '')
            message = f"Hello {name}, your verification code is {otp}. Valid for 5 minutes."
            payload = {
                'chatId': f"{formatted_number}@c.us",
                'contentType': 'string',
                'content': message,
            }
            headers = {'Content-Type': 'application/json'}
            response = requests.post(WHATSAPP_API_URL, json=payload, headers=headers, timeout=10)
            
            if response.status_code == 200 and response.json().get('success'):
                logger.info(f"WhatsApp OTP sent to {phone_number}: {otp}")
                return True
            logger.error(f"WhatsApp API error: {response.text}")
            return False
        except Exception as e:
            logger.error(f"WhatsApp send failed: {str(e)}")
            return False