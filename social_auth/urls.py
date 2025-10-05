from django.urls import path
from . import views

urlpatterns = [
    path('google/', views.GoogleSocialAuthView.as_view(), name='google-auth'),
    path('facebook/', views.FacebookSocialAuthView.as_view(), name='facebook-auth'),
    path('x/', views.XSocialAuthView.as_view(), name='x-auth'),
    path('github/', views.GitHubSocialAuthView.as_view(), name='github-auth'),
]