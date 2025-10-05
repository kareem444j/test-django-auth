from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import (LoginSerializer, UserCreateSerializer, PasswordChangeSerializer)
from django.contrib.auth.models import User
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.tokens import TokenError
from rest_framework.permissions import IsAuthenticated
from .authentication import CookieJWTAuthentication
from django.core.mail import EmailMultiAlternatives

# csrf Requirements > to get csrf token
from django.conf import settings
from django.middleware.csrf import get_token
from django.http import JsonResponse

# register token generators
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.urls import reverse
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str

# use axes to limit login attempts
from axes.decorators import axes_dispatch
from django.utils.decorators import method_decorator
from axes.handlers.proxy import AxesProxyHandler

# import to sending html email
from django.template.loader import render_to_string
from django.core.mail import EmailMultiAlternatives

def send_html_email(subject, to_email, context, form_type=None):
    html_content = render_to_string("emails/welcome.html", context)
    text_content = "Your account not created.!"  # default text content
    
    if form_type == "reset":
        html_content = render_to_string("emails/reset.html", context)
        text_content = "Your password not reset.!"  # default text content

    msg = EmailMultiAlternatives(subject, text_content, "kareem147j@gmail.com", [to_email])
    msg.attach_alternative(html_content, "text/html")
    msg.send()


# csrf tokens
"""
if you don't want to use csrf in your app remove it from settings.py > MIDDLEWARE > DoubleSubmitCSRFMiddleware
"""
class GetCSRFTokenView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []

    def get(self, request):
        token = get_token(request) 
        response = JsonResponse({"csrfToken": token})
        # set cookie so frontend JS can read it (httponly=False)
        response.set_cookie(
            "csrftoken",
            token,
            max_age=60 * 60 * 24,  
            secure=getattr(settings, "CSRF_COOKIE_SECURE", False),
            httponly=False,
            samesite=getattr(settings, "CSRF_COOKIE_SAMESITE", "Lax"),
            path="/"
        )
        return response

# ###########
""" 
use this function if you want to set csrf token in cookie for any response & if you are not using GetCSRFTokenView(end point)
& make sure your requests to (login | register | refresh) > is EXEMPT_URLS in middleware from settings.py > CSRF_EXEMPT_URLS
"""
# def set_csrf_token_in_cookie(request, response):
#     csrf_token = get_token(request)
#     response.set_cookie(
#         "csrftoken",
#         csrf_token,
#         max_age=60*60*24,
#         secure=not settings.DEBUG,   # استخدم True في production
#         httponly=False,
#         samesite="None" if not settings.DEBUG else "Lax",
#         path="/"
#     )

##################################################################
# login view
@method_decorator(axes_dispatch, name='dispatch')
class LoginView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []
    def post(self, request, *args, **kwargs):
        username = request.data.get('username')
        password = request.data.get('password')
        
        user = LoginSerializer(data={'username': username, 'password': password})
        if not user.is_valid():
            return Response(user.errors, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user_obj = User.objects.get(username=username)
        except User.DoesNotExist:
            user_obj = None
            
        if user_obj and not user_obj.is_active:
            AxesProxyHandler.user_login_failed(
                sender=LoginView,
                credentials={'username': username},
                request=request
            )
            
            # uid + token
            uid = urlsafe_base64_encode(force_bytes(user_obj.pk))
            token = token_generator.make_token(user_obj)

            activation_link = request.build_absolute_uri(
                reverse("activate-account", kwargs={"uidb64": uid, "token": token})
            )

            # send email
            send_html_email(
                "Account activation",
                user_obj.email,
                {
                    "username": user_obj.username,
                    "email": user_obj.email,
                    "verification_link": activation_link
                }
            )
    
            return Response({'detail': f'Your account is not activated, please check your email to activate your account', 'code': 'user_inactive'}, status=status.HTTP_403_FORBIDDEN)
        
        user = authenticate(request, username=username, password=password)
        
        if user is None:
            # use axes > record failed login attempt
            AxesProxyHandler.user_login_failed(
                sender=LoginView,
                credentials={'username': username},
                request=request
            )
            return Response({'detail': 'Username or password is invalid'}, status=status.HTTP_401_UNAUTHORIZED)
        
        # reset axes when login successfully
        AxesProxyHandler.user_logged_in(
            sender=LoginView,
            request=request,
            user=user
        )
        
        
        refresh = RefreshToken.for_user(user)
        access = refresh.access_token
        access['username'] = user.username
        
        response = Response({
            'access': str(access),
            'refresh': str(refresh),
            'username': user.username,
            'email': user.email,
            'message': 'Login successful'
        }, status=status.HTTP_200_OK)
        
        response.set_cookie(
            key='access',
            value=str(access),
            httponly=True,
            max_age = 60 * 60, 
            path="/",
            secure=True, 
            samesite='None'
        )
        
        response.set_cookie(
            key='refresh',
            value=str(refresh),
            httponly=True,
            max_age = 60 * 60 * 24 * 1, 
            path="/",
            secure=True, 
            samesite='None'
        )
        
        # use it here if you want
        # set_csrf_token_in_cookie(request, response)
        
        return response
    
    def get(self, request):
        return Response({'detail': 'Use POST method to login'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
##################################################################


##################################################################
# register view
token_generator = PasswordResetTokenGenerator()
class RegisterView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []
    def post(self, request, *args, **kwargs):
        username = request.data.get('username')
        password = request.data.get('password')
        confirm_password = request.data.get('confirm_password')
        email = request.data.get('email') 
        
        user = UserCreateSerializer(data={
            'username':username,
            'password':password,
            'confirm_password':confirm_password,
            'email': email
        })
        
        if not user.is_valid():
            return Response(user.errors, status=status.HTTP_400_BAD_REQUEST)
        
        user = User.objects.create_user(username=username, password=password, email=email, is_active=False)
        user.save()
        
        # uid + token
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = token_generator.make_token(user)

        activation_link = request.build_absolute_uri(
            reverse("activate-account", kwargs={"uidb64": uid, "token": token})
        )
        
        # ====== send email ======
        send_html_email(
            "Account activation", 
            email, 
            {
                'username': username,
                'email': email,
                'verification_link': activation_link
            }
            )
        # ========================
        
        refresh = RefreshToken.for_user(user)
        access = refresh.access_token
        access['username'] = user.username
        
        response = Response({
            'access': str(access),
            'refresh': str(refresh),
            'username': user.username,
            'email': user.email,
            'message': 'Registration successful, please check your email to activate your account'
        }, status=status.HTTP_201_CREATED)
        
        response.set_cookie(
            key='access',
            value=str(access),
            httponly=True,
            max_age = 60 * 60, 
            path="/",
            secure=True, 
            samesite='None'
        )
        
        response.set_cookie(
            key='refresh',
            value=str(refresh),
            httponly=True,
            max_age = 60 * 60 * 24 * 1,
            path="/",
            secure=True, 
            samesite='None'
        )
        
        return response

# activate account view
class ActivateAccountView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []

    def get(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user is not None and token_generator.check_token(user, token):
            user.is_active = True
            user.save()
            return Response({"message": "account activated"}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Invalid activation link or expired"}, status=status.HTTP_400_BAD_REQUEST)
##################################################################


##################################################################
# refresh token view
class RefreshTokenView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []
    
    def post(self,request, *args, **kwargs):
        refresh_token = request.COOKIES.get('refresh')
        if not refresh_token:
            return Response({'detail': 'Refresh token not found'}, status=status.HTTP_401_UNAUTHORIZED)
        
        try:
            refresh = RefreshToken(refresh_token)
            access = refresh.access_token
            
            # send username with access token if needed
            user_id = refresh['user_id']
            from django.contrib.auth.models import User
            if User.objects.filter(id=user_id).exists():
                user = User.objects.get(id=user_id)
                access['username'] = user.username
            else:
                return Response({'detail': 'User not found'}, status=status.HTTP_401_UNAUTHORIZED)
            
            response = Response({
                'access': str(access),
                'message': 'Token refreshed successfully'
            }, status=status.HTTP_200_OK)
            
            response.set_cookie(
                key='access',
                value=str(access),
                max_age=60 * 60,
                httponly=True,
                path="/",
                secure=True, 
                samesite='None'
            )
            
            return response
        except TokenError:
            return Response({'detail': 'Refresh token is invalid or expired'}, status=status.HTTP_401_UNAUTHORIZED)
##################################################################


##################################################################
# logout view 
class LogoutView(APIView):
    permission_classes = [IsAuthenticated]  
    authentication_classes = [CookieJWTAuthentication] 
    
    def post(self, request, *args, **kwargs):
        # use token blacklist if you enabled it in settings.py
        refresh_token = request.COOKIES.get("refresh")
        if refresh_token:
            try:
                token = RefreshToken(refresh_token)
                token.blacklist() # blacklist the refresh token
            except Exception:
                pass
        ## clear cookies
        response = Response({'message': 'Logout successful'}, status=status.HTTP_200_OK)
        response.delete_cookie('access', path='/', domain=None, samesite='None')
        response.delete_cookie('refresh', path='/', domain=None, samesite='None')
        response.delete_cookie('sessionid', path='/', domain=None, samesite='None') # if you are using sessions
        return response
##################################################################


##################################################################
# Password Management
##################################################################
# change password
class PasswordChangeView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [CookieJWTAuthentication]
    
    def post(self, request):
        serializer = PasswordChangeSerializer(data=request.data, context={'request': request})
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        serializer.save()
        return Response({'message': 'Password updated successfully'}, status=status.HTTP_200_OK)

# forgot password
class PasswordForgotRequestView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []
    
    def post(self, request):
        email = request.data.get("email")
        if not email:
            return Response({"error": "Email is required"}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"detail": "user with this email does not exist"}, status=status.HTTP_200_OK)
        
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = token_generator.make_token(user)
        
        reset_link = request.build_absolute_uri(
            reverse("password-reset", kwargs={"uidb64": uid, "token": token})
        )
        
        send_html_email(
            "Password Reset Request",
            email,
            {
                "username": user.username,
                "email": user.email,
                "reset_link": reset_link
            },
            form_type="reset"
        )
        
        return Response({"detail": "If this email exists, you will receive a reset link"}, status=status.HTTP_200_OK)

class PasswordForgotResetView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []

    def post(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user is None or not token_generator.check_token(user, token):
            return Response({"error": "Invalid or expired token"}, status=status.HTTP_400_BAD_REQUEST)

        new_password = request.data.get("new_password")
        confirm_password = request.data.get("confirm_password")

        if not new_password or not confirm_password:
            return Response({"error": "Both password fields are required"}, status=status.HTTP_400_BAD_REQUEST)

        if new_password != confirm_password:
            return Response({"error": "Passwords do not match"}, status=status.HTTP_400_BAD_REQUEST)
        
        if len(new_password) < 8:
            return Response({"error": "Password must be at least 8 characters long"}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.save()

        return Response({"detail": "Password has been reset successfully"}, status=status.HTTP_200_OK)        
##################################################################


##################################################################
# authentication test end points
class CheckTokenView(APIView):
    authentication_classes = [CookieJWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        access_token = request.COOKIES.get('access')
        if not access_token or access_token is None:
            return Response({'detail': 'No access token provided'}, status=status.HTTP_401_UNAUTHORIZED)
        
        user = request.user
        user_context = {
            'id': user.id,
            'username': user.username,
            'email': user.email or 'no email provided',
            'first_name': user.first_name or 'no first name provided',
            'last_name': user.last_name or 'no last name provided'  
        }
        
        return Response({'data': user_context, 'message':'User is authenticated'}, status=status.HTTP_200_OK)

class ProfileView(APIView):
    permission_classes = [IsAuthenticated]  
    authentication_classes = [CookieJWTAuthentication]  
    
    def get(self, request):
        user = request.user
        return Response({
            'username': user.username,
            'message': 'You are authenticated!'
        })
##################################################################