import random
import logging
from django.core.cache import cache
from django.utils import timezone
from datetime import datetime
from django.conf import settings
from .base import BaseEmailService

otp_logger = logging.getLogger("otp")


class OTPEmailService(BaseEmailService):
    def __init__(self):
        super().__init__()
        self.otp_timeout = getattr(settings, "OTP_TIMEOUT", 300)
        self.COOLDOWN_SECONDS = 30

    def _get_otp_catch_key(self, email):
        return f"otp_{email}"

    def _generate_otp(self):
        return str(random.randint(100000, 999999))

    def can_resend_otp(self, email):
        catch_key = self._get_otp_catch_key(email)
        data = cache.get(catch_key)

        if not data:
            return True, None
        created_at = datetime.fromisoformat(data["created_at"])
        seconds_passed = (timezone.now() - created_at).total_seconds()
        if seconds_passed < self.COOLDOWN_SECONDS:
            wait_time = int(self.COOLDOWN_SECONDS - seconds_passed)
            return False, wait_time

        return True, None

    def sent_otp(self, email, user_name=None, extra_context=None):
        otp = self._generate_otp()

        context = {
            "otp": otp,
            "timeout_minutes": self.otp_timeout // 60,
            "user_name": user_name,
            **(extra_context or {}),
        }

        success = self._sent_email(
            subject="Your Verification Code",
            recipient_list=[email],
            template_name="emails/auth/registration_otp.html",
            text_template="emails/auth/registration_otp.txt",
            context=context,
        )

        if success:
            catch_key = self._get_otp_catch_key(email)
            catch_data = {
                "otp": otp,
                "attempts": 0,
                "max_attempts": 3,
                "created_at": timezone.now().isoformat(),
            }
            cache.set(catch_key, catch_data)
            otp_logger.info(f"OTP sent to {email}")

        return success

    def verify_otp(self, email, user_otp):
        try:
            catch_key = self._get_otp_catch_key(email)
            stored_data = cache.get(catch_key)

            if not stored_data:
                return False, "OTP has expired or Doesn't exits."

            if stored_data["attempts"] >= stored_data["max_attempts"]:
                cache.delete(catch_key)
                return False, "Maximum OTP attempts exceeded. Please request a new OTP."

            if stored_data["otp"] != user_otp:
                stored_data["attempts"] += 1
                cache.set(catch_key, stored_data, timeout=self.otp_timeout)
                return False, "OTP doesn't match. Please try again."

            return True, "OTP verify successfully."

        except Exception as e:
            error_msg = f"OTP verification error for {email}, {str(e)}"
            otp_logger.error(error_msg)
            return False, "OTP verification failed. Please try again."
    
    def verify_account_remove_otp(self,  email):
        try:
            catch_key = self._get_otp_catch_key(email)
            cache.delete(catch_key)
            return True, "OTP removed successfully."
        except Exception as e:
            return False, "Can't removed OTP"
            
        

    