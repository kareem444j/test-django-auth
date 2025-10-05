from django.contrib.auth.models import User
from rest_framework import serializers
from .models import Note

# Note Serializer
class NoteSerializer(serializers.ModelSerializer):
    class Meta:
        model = Note
        fields = ['id', 'title', 'content', 'created_at', 'author']
        extra_kwargs = {
            'author': {'read_only': True},
        }

# User
class UserSerializer(serializers.ModelSerializer):
    # create confirm password field
    confirm_password = serializers.CharField(write_only=True, style={"input_type": "password"}, required=False)
    class Meta:
        model = User
        fields = ['id', 'username', 'password', 'confirm_password'] # include confirm password field
        extra_kwargs = {
            "password": {
                "write_only": True,
                "style": {"input_type": "password"},
                "error_messages": {
                    "blank": "Password field cannot be empty or whitespace.",
                    "required": "Password field is required."
                }
            },
            "username": {
                "error_messages": {
                    "blank": "Username field cannot be empty or whitespace.",
                    "required": "Username field is required."
                }
            }
        }
        
    # make some custom validations
    def validate_password(self, value):
        if not value or not value.strip():
            raise serializers.ValidationError("Password field cannot be empty or whitespace.")
        if len(value) < 8:
            raise serializers.ValidationError("password must be at least 8 characters long")
        return value
    
    def validate_username(self, value):
        if not value or not value.strip():
            raise serializers.ValidationError("Username field cannot be empty or whitespace.")
        if len(value) < 4:
            raise serializers.ValidationError("username must be at least 4 characters long")
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError("username is already taken")
        return value
        
    def validate(self, attrs):
        if attrs['password'] == attrs['username']:
            raise serializers.ValidationError({"detail":"Password cannot be the same as the username."})
        return attrs
        
    # override the create method
    def create(self, validated_data):
        password = validated_data.pop('password', None)
        confirm_password = validated_data.pop('confirm_password', None)
        if not password or not password.strip():
            raise serializers.ValidationError({"password": "This field is required."})
        
        # check if confirm password is provided
        if password != confirm_password:
            raise serializers.ValidationError({"password": "Password fields didn't match."})
        
        user = User.objects.create(**validated_data)
        user.set_password(password)
        user.save()
        return user