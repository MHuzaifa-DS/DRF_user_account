from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from .utils import CustomUserManager, validate_email_domain
from django.conf import settings

class User(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(max_length=100, unique=True)
    email = models.EmailField(max_length=100, unique=True, validators=[validate_email_domain])
    phone_number = models.CharField(max_length=20, blank=True, null=True)
    profile_image = models.ImageField(upload_to='profile_images/', blank=True , null=True)

    is_active = models.BooleanField(default=False) 
    is_staff = models.BooleanField(default=False)   

    objects = CustomUserManager()

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email', 'phone_number']

    def __str__(self):
        return self.username
    
class Post(models.Model):
    auther = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    caption = models.TextField()
    image = models.ImageField(upload_to='post_images/', blank=True , null=True)
    created_at = models.DateTimeField()
    updated_at = models.DateTimeField()


