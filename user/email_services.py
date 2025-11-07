import random
import logging
from django.core.mail import send_mail
from django.conf import settings
from django.core.cache import cache
from django.template.loader import render_to_string
from django.utils.html import strip_tags
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
            subject, plain_message, html_message = self._prepare_otp_email(otp, purpose)
            send_mail(
                subject,
                plain_message,
                self.from_email,
                [email],
                fail_silently=False,
                html_message=html_message
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
        """Prepare email subject and message based on purpose using HTML templates"""
        
        template_map = {
            "registration": {
                "subject": "Complete Your Registration - OTP Verification",
                "template": "emails/registration_otp.html"
            },
            "password_reset": {
                "subject": "Password Reset - OTP Verification",
                "template": "emails/password_reset_otp.html"
            }
        }
        
        email_config = template_map.get(purpose, {
            "subject": "Your OTP Code",
            "template": "emails/registration_otp.html"  # fallback to registration template
        })
        
        # Render HTML email
        html_message = render_to_string(
            email_config["template"],
            {'otp': otp}
        )
        
        # Create plain text version
        plain_message = strip_tags(html_message)
        
        return email_config["subject"], plain_message, html_message
