from django.urls import path
from .views import *

urlpatterns = [
    # tokens
    path('token/', LoginView.as_view(), name='get-token'),
    path('token/refresh/', RefreshTokenView.as_view(), name='refresh'),
    
    # user
    path('user/register/', RegisterView.as_view(), name='register'),
    path("user/activate/<uidb64>/<token>/", ActivateAccountView.as_view(), name="activate-account"),
    path('logout/', LogoutView.as_view(), name='logout'),
    
    # passwords
    path('user/change-password/', PasswordChangeView.as_view(), name='change-password'),
    path("user/forgot-password/", PasswordForgotRequestView.as_view(), name="forgot-password"),
    path("user/password-reset/<uidb64>/<token>/", PasswordForgotResetView.as_view(), name="forgot-password-confirm"),
    
    # check auth
    path('user/check-auth/', CheckTokenView.as_view(), name='check-auth'),
    path('user/profile/', ProfileView.as_view(), name='user.profile'),
    
    # csrf > optional if you want to use csrf protection
    # use this endpoint to get csrf token and set it in cookies
    path("get-csrf/", GetCSRFTokenView.as_view(), name="get-csrf"),
]