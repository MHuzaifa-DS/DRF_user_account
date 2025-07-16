# from django.contrib.auth.models import BaseUserManager
# from django.core.exceptions import ValidationError
# import re


# def validate_strong_password(value):
#     if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d]{8,16}$', value):
#         raise ValidationError(
#             'Password must be 8-16 characters and include uppercase, lowercase, and a number.'
#         )

# def validate_email_domain(value):
#     value = value.strip().lower() 
#     pattern = r'^[\w\.-]+@(?:gmail\.com|yahoo\.com)$'
#     if not re.match(pattern, value):
#         raise ValidationError('Email must be from gmail.com or yahoo.com.')
    

# def create_user(self, username, email, password=None, phone_number=None, **extra_fields):
#     if not email:
#         raise ValueError("Users must have an email address")

#     email = self.normalize_email(email)
#     user = self.model(
#         username=username,
#         email=email,
#         phone_number=phone_number,
#         **extra_fields
#     )
#     user.set_password(password)
#     user.save()

#     # Correctly set groups if needed
#     groups = extra_fields.get('groups', None)
#     if groups:
#         user.groups.set(groups)

#     return user

    
# def create_superuser(self, username, email, password, phone_number=None, profile_image=None):
#     user = self.create_user(username, email, password, phone_number,profile_image)
#     user.is_superuser = True
#     user.is_staff = True   
#     user.save()
#     return user


from django.contrib.auth.models import BaseUserManager
from django.core.exceptions import ValidationError
import re

# Email domain validation (only Gmail/Yahoo)
def validate_email_domain(value):
    allowed_domains = ['gmail.com', 'yahoo.com']
    domain = value.split('@')[-1]
    if domain not in allowed_domains:
        raise ValidationError("Only Gmail and Yahoo emails are allowed.")

# Strong password validation
def validate_strong_password(password):
    if not re.search(r'[A-Z]', password):
        raise ValidationError("Password must contain at least one uppercase letter.")
    if not re.search(r'[a-z]', password):
        raise ValidationError("Password must contain at least one lowercase letter.")
    if not re.search(r'[0-9]', password):
        raise ValidationError("Password must contain at least one number.")
    if len(password) < 8 or len(password) > 16:
        raise ValidationError("Password must be between 8 and 16 characters long.")


# Custom user manager
class CustomUserManager(BaseUserManager):
    def create_user(self, username, email, phone_number=None, password=None, **extra_fields):
        if not username:
            raise ValueError('The Username field is required')
        if not email:
            raise ValueError('The Email field is required')

        email = self.normalize_email(email)

        # Remove m2m fields if present to handle them separately
        groups = extra_fields.pop('groups', None)
        permissions = extra_fields.pop('user_permissions', None)

        user = self.model(
            username=username,
            email=email,
            phone_number=phone_number,
            **extra_fields
        )
        user.set_password(password)
        user.save()

        # Set m2m fields after saving
        if groups:
            user.groups.set(groups)
        if permissions:
            user.user_permissions.set(permissions)

        return user

    def create_superuser(self, username, email, phone_number=None, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True')

        return self.create_user(username, email, phone_number, password, **extra_fields)
