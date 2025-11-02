import random
import logging
from django.core.mail import send_mail
from django.conf import settings
from django.core.cache import cache
from smtplib import SMTPAuthenticationError

"""
    How to do EmailService works:
    1. OTP generate = "123456" ✓
    2. Email content prepare ✓
    3. Email send from: minhajurrohoman9016@gmail.com ✓
    4. Email send to: user@example.com ✓  
    5. OTP store in cache: key='otp_user@example.com', value='123456' ✓
"""
email_logger = logging.getLogger("emails")
otp_logger = logging.getLogger("otp")

class EmailService:
    def __init__(self):
        self.from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', 'minhajurrohoman9016@gmail.com')
        
        
    def sent_otp(self, email, purpose):
        """
            Sent OTP to email address
        """
        # Generate the OTP
        otp = str(random.randint(10000, 999999))

        try:
            # Prepare email content
            subject, message = self._prepare_otp_email(otp, purpose)
            send_mail(
                subject,
                message,
                self.from_email,
                [email],
                fail_silently=False,
            )
            cache_key = f'otp_{email}'
            cache.set(cache_key, otp, timeout=300)
            print(f"OTP {otp} sent to your {email} for {purpose}")
            return otp
        
        except SMTPAuthenticationError as e:
            error_msg = f"Gmail authentication failed for {email}: {str(e)}"
            print(f"❌ {error_msg}")
            otp_logger.error(error_msg, exc_info=True)
            return None
        
        
        except Exception as e:
            print(f"❌ Failed to send OTP to {email}: {str(e)}")
            
            # ✅ Log error with details
            otp_logger.error(f"Failed to send OTP to {email}: {str(e)}", exc_info=True)
            email_logger.error(f"Email sending failed to {email}: {str(e)}")
            
            return None

    def _prepare_otp_email(self, otp, purpose):
        """Prepare email subject and message based on purpose"""

        if purpose == "registration":
            subject = "Complete Your Registration - OTP Verification"
            message = f"""
            Welcome! Complete your registration with this OTP:
            
            Your OTP Code: {otp}
            
            This OTP is valid for 5 minutes.
            
            Enter this code in the verification page to activate your account.
            
            If you didn't request this, please ignore this email.
            
            Best regards,
            Tecgen Soft
            """
        elif purpose == "password_reset":
            subject = "Password Reset - OTP Verification"
            message = f"""
            Password Reset Request
            
            Your OTP Code: {otp}
            
            This OTP is valid for 5 minutes.
            
            Enter this code to reset your password.
            
            If you didn't request a password reset, please ignore this email.
            
            Best regards,
            Tecgen Soft
            """
        else:
            subject = "Your OTP Code"
            message = f"""
            Your OTP Code: {otp}
            
            This OTP is valid for 5 minutes.
            
            Best regards,
            Tecgen Soft
            """

        return subject, message
