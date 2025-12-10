import logging
from django.core.mail import EmailMultiAlternatives
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from smtplib import SMTPAuthenticationError
from datetime import datetime
from decouple import config

email_logger = logging.getLogger("emails")
from core.utils.error_formatter import format_error_log


class BaseEmailService:
    def __init__(self):
        self.from_email = getattr(
            settings, "DEFAULT_FROM_EMAIL", "minhajurrohoman9016@gmail.com"
        )
        self.support_email = getattr(
            settings, "DEFAULT_FROM_EMAIL", "minhajurrohoman9016@gmail.com"
        )

    def _sent_email(
        self,
        subject,
        recipient_list,
        template_name,
        context,
        text_template=None,
        cc=None,
        bcc=None,
    ):
        try:
            context = self._prepare_email_context(**context)
            html_message = render_to_string(template_name, context)
            plain_message = strip_tags(html_message)
            
            if text_template:
                plain_message = render_to_string(text_template, context)

            email = EmailMultiAlternatives(
                subject=subject,
                body=plain_message,
                from_email=self.from_email,
                to=recipient_list,
                cc=cc,
                bcc=bcc,
            )

            email.attach_alternative(html_message, "text/html")
            email.send(
                fail_silently=False
            )  # False because of i want to notify email sent failed

            email_logger.info(
                f"[{datetime.now().strftime('%Y-%m-%d %H-%M-%S')}] Email sent successfully to {recipient_list} - Subject {subject}"
            )

            return True

        except SMTPAuthenticationError as e:
            error_msg = f"Email authentication failed for {recipient_list}: {str(e)}"
            email_logger.error(error_msg, exc_info=True)
            
            return False

        except Exception as e:
            detailed_log = format_error_log(e)
            error_msg = f"Failed to sent email to {recipient_list}: {str(e)}"
            email_logger.error(error_msg, exc_info=True)
            print(detailed_log)
            return False

    def _prepare_email_context(self, **kwargs):
        base_context = {
            "company_name": config("COMPANY_NAME"),
            "support_email": config("COMPANY_EMAIL"),
        }
        base_context.update(kwargs)
        return base_context
