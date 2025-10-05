from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth import get_user_model
from . import google, facebook, xhelpper, github
from django.conf import settings
from .register import register_social_user
import re

User = get_user_model()

class GoogleAuthSerializer(serializers.Serializer):
    auth_token = serializers.CharField()
    
    def validate_auth_token(self, auth_token):
        user_data = google.Google.validate(auth_token)
        
        if not user_data:
            raise serializers.ValidationError('The token is invalid or expired. Please login again.')
        
        if user_data['aud'] != settings.GOOGLE_CLIENT_ID:
            raise AuthenticationFailed('Audience does not match')
        
        user_id = user_data['sub']
        email = user_data['email']
        name = user_data.get('name', '') 
        
        # get base username from email
        base_username = email.split('@')[0]

        # remove any characters that are not alphanumeric, dot, underscore, or hyphen
        base_username = re.sub(r'[^a-zA-Z0-9._-]', '', base_username)

        username = base_username

        return register_social_user(
            user_id=user_id,
            username=username,
            email=email,
            name=name
        )
        
class FacebookAuthSerializer(serializers.Serializer):
    code = serializers.CharField()

    def validate_code(self, code):
        user_data = facebook.Facebook.exchange_code_for_user_data(code)
        if not user_data:
            raise serializers.ValidationError('The code is invalid or expired. Please login again.')
        
        user_id = user_data['id']
        email = user_data['email']
        name = user_data.get('name', '') 
        
        base_username = email.split('@')[0]
        base_username = re.sub(r'[^a-zA-Z0-9._-]', '', base_username)
        username = base_username

        return register_social_user(
            user_id=user_id,
            username=username,
            email=email,
            name=name
        )

class GitHubAuthSerializer(serializers.Serializer):
    code = serializers.CharField()

    def validate(self, attrs):
        code = attrs.get("code")
        user_data = github.GitHubAuth.exchange_code_for_user_data(code)

        if not user_data:
            raise serializers.ValidationError("The code is invalid or expired. Please login again.")

        return register_social_user(
            user_id=user_data["id"],
            username=user_data["username"],
            email=user_data["email"],
            name=user_data["name"]
        )


class XAuthSerializer(serializers.Serializer):
    code = serializers.CharField()

    def validate(self, attrs):
        code = attrs.get("code")
        user_data = xhelpper.XAuth.exchange_code_for_user_data(code)

        if not user_data:
            raise serializers.ValidationError("The code is invalid or expired. Please login again.")

        user_id = user_data['id']
        email = user_data['email']
        name = user_data.get('name', '')
        base_username = user_data.get('username', email.split('@')[0])
        base_username = re.sub(r'[^a-zA-Z0-9._-]', '', base_username)
        username = base_username

        # هنا نرجع كل البيانات كـ validated_data
        result = register_social_user(
            user_id=user_id,
            username=username,
            email=email,
            name=name
        )
        return result