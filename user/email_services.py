import random
from django.core.mail import send_mail
from django.conf import settings
from django.core.cache import cache


class EmailService:
    def __init__(self):
        self.from_email = "Minhajur Rohman <minhajurrohoman9016@gmail.com>"
        self.support_email = "minhajurrohoman9016@gmail.com"

        otp = str(random.randint(10000, 90000))
        




