from rest_framework.views import exception_handler
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError

def custom_exception_handler(exc, context):
    response = exception_handler(exc, context)

    if isinstance(exc, (InvalidToken, TokenError)):
        return Response({
            "detail": "Authentication credentials are invalid or expired. Please log in again."
        }, status=status.HTTP_401_UNAUTHORIZED)
    
    if response is not None:
        if response.data.get('code') == 'user_inactive':
            response.data['detail'] = 'Your account is not activated'
        elif response.data.get('detail') == 'User is inactive':
            response.data['detail'] = 'Your account is not activated'

    return response
