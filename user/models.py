from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
import uuid

#model stores the user details
class CustomUser(AbstractUser):
    username = models.CharField(
        max_length=150,
        unique=True,
        error_messages={
            'unique': "A user with that username already exists.",
        },
    )
    email = models.EmailField(unique = True)
    PKA = models.BooleanField(default=False)
    unique_id = models.UUIDField(default=uuid.uuid4,editable=False,null=True,blank=True)
    verified = models.BooleanField(null=True,blank=True)
    USERNAME_FIELD = 'username'


#model to store the messages
class Message(models.Model):
    recipient = models.ForeignKey(CustomUser, on_delete = models.CASCADE, related_name='received_messages')
    sender = models.ForeignKey(CustomUser, on_delete = models.CASCADE, related_name='sent_messages')
    message = models.TextField()
    timestamp = models.DateTimeField(default = timezone.now)
    
    def __str__(self) -> str:
        return f"From:{self.sender}--To:{self.recipient}"


#model stores the otp
class Otp(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6, null=True, blank=True)
    otp_validated = models.BooleanField(default=False, blank=True)