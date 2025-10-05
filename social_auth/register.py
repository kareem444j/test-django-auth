from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate
from django.conf import settings
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.exceptions import AuthenticationFailed
import re

User = get_user_model()


def register_social_user(user_id, username, email, name):
    # Check if email is valid
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        raise AuthenticationFailed(
            detail='No valid email returned from provider, Please sign up using your email and password.'
        )
        
    filtered_user_by_email = User.objects.filter(email=email)

    if filtered_user_by_email.exists():
        registered_user = authenticate(
            username=filtered_user_by_email[0].username,
            password=settings.SOCIAL_SECRET_KEY
        )
        
        if not registered_user:
            raise AuthenticationFailed(
                detail='User with this email exists, please login using your email and password'
            )
            
        refresh = RefreshToken.for_user(registered_user)
        access = refresh.access_token
        access['username'] = registered_user.username

        return {
            'access': str(access),
            'refresh': str(refresh),
            'username': registered_user.username,
            'email': registered_user.email,
            'message': 'Login successful'
        }
    else:
        user = User.objects.create_user(
            username=username,
            email=email,
            password=settings.SOCIAL_SECRET_KEY
        )
        
        user.is_active = True
        user.save()
        registered_user = user

        refresh = RefreshToken.for_user(registered_user)
        access = refresh.access_token
        access['username'] = registered_user.username

        return {
            'access': str(access),
            'refresh': str(refresh),
            'username': registered_user.username,
            'email': registered_user.email,
            'message': 'Registration successful'
        }