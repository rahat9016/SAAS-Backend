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

    def _get_otp_catch_key(self, email, purpose):
        return f"otp_{purpose}_{email}"

    def _generate_otp(self):
        return str(random.randint(100000, 999999))

    def can_resend_otp(self, email, purpose):
        catch_key = self._get_otp_catch_key(email, purpose)
        data = cache.get(catch_key)

        if not data:
            return True, None
        created_at = datetime.fromisoformat(data["created_at"])
        seconds_passed = (timezone.now() - created_at).total_seconds()
        if seconds_passed < self.COOLDOWN_SECONDS:
            wait_time = int(self.COOLDOWN_SECONDS - seconds_passed)
            return False, wait_time

        return True, None

    def sent_otp(self, email, purpose, user_name=None, extra_context=None):
        otp = self._generate_otp()

        context = {
            "otp": otp,
            "purpose": purpose,
            "timeout_minutes": self.otp_timeout // 60,
            "user_name": user_name,
            **(extra_context or {}),
        }

        template_map = {
            "registration": {
                "subject": "Verify Your Account",
                "template": "emails/auth/registration_otp.html",
                "text_template": "emails/auth/registration_otp.txt",
            },
            "resend_otp": {
                "subject": "New Verification Code",
                "template": "emails/auth/resend_otp.html",
                "text_template": "emails/auth/resend_otp.txt",
            },
            "password_reset": {
                "subject": "Reset Your Password - OTP Verification",
                "template": "emails/auth/password_reset_otp.html",
                "text_template": "emails/auth/password_reset_otp.txt",
            },
        }

        email_config = template_map.get(
            purpose,
            {
                "subject": "Your Verification Code",
                "template": "emails/auth/registration_otp.html",
                "text_template": "emails/auth/registration_otp.txt",
            },
        )
        success = self._sent_email(
            subject=email_config["subject"],
            recipient_list=[email],
            template_name=email_config["template"],
            text_template=email_config["text_template"],
            context=context,
        )

        if success:
            catch_key = self._get_otp_catch_key(email, purpose)
            catch_data = {
                "otp": otp,
                "attempts": 0,
                "max_attempts": 3,
                "created_at": timezone.now().isoformat(),
            }
            cache.set(catch_key, catch_data)
            otp_logger.info(f"OTP sent to {email} for {purpose}")

        return success

    def verify_otp(self, email, user_otp, purpose):
        try:
            catch_key = self._get_otp_catch_key(email, purpose)
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

            cache.delete(catch_key)
            return True, "OTP verify successfully."

        except Exception as e:
            error_msg = f"OTP verification error for {email}, {str(e)}"
            otp_logger.error(error_msg)
            return False, "OTP verification failed. Please try again."

    def resend_otp(self, email, purpose, user_name=None, extra_context=None):
        otp = self._generate_otp()
        context = {
            "otp": otp,
            "purpose": purpose,
            "timeout_minutes": self.otp_timeout // 60,
            "user_name": user_name,
            **(extra_context or {}),
        }

        success = self._sent_email(
            subject="New Verification Code",
            recipient_list=[email],
            template_name="emails/auth/resend_otp.html",
            text_template=None,
            context=context,
        )

        if success:
            catch_key = self._get_otp_catch_key(email, purpose)
            catch_data = {
                "otp": otp,
                "attempts": 0,
                "max_attempts": 3,
                "created_at": timezone.now().isoformat(),
            }
            cache.set(catch_key, catch_data)
            otp_logger.info(f"OTP sent to {email} for {purpose}")

        return success
