from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import (
    GoogleAuthSerializer,
    FacebookAuthSerializer,
    XAuthSerializer,
    GitHubAuthSerializer,
)


class GoogleSocialAuthView(APIView):
    permission_classes = []
    authentication_classes = []
    serializer_class = GoogleAuthSerializer

    def post(self, request):
        """
        POST with "auth_token"
        Send an id_token as from google to get user information
        """
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        data = serializer.validated_data["auth_token"]

        response = Response(data, status=status.HTTP_200_OK)

        response.set_cookie(
            key="access",
            value=data["access"],
            httponly=True,
            max_age=60 * 60,
            path="/",
            secure=True,
            samesite="None",
        )
        response.set_cookie(
            key="refresh",
            value=data["refresh"],
            httponly=True,
            max_age=60 * 60 * 24 * 1,
            path="/",
            secure=True,
            samesite="None",
        )

        return response


class FacebookSocialAuthView(APIView):
    permission_classes = []
    authentication_classes = []
    serializer_class = FacebookAuthSerializer

    def post(self, request):
        """
        POST with "auth_token"
        Send an access token as from facebook to get user information
        """
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        data = serializer.validated_data["code"]

        response = Response(data, status=status.HTTP_200_OK)

        response.set_cookie(
            key="access",
            value=data["access"],
            httponly=True,
            max_age=60 * 60,
            path="/",
            secure=True,
            samesite="None",
        )
        response.set_cookie(
            key="refresh",
            value=data["refresh"],
            httponly=True,
            max_age=60 * 60 * 24 * 1,
            path="/",
            secure=True,
            samesite="None",
        )

        return response


class GitHubSocialAuthView(APIView):
    permission_classes = []
    authentication_classes = []
    serializer_class = GitHubAuthSerializer

    def post(self, request):
        """
        POST with "code"
        Send authorization code from GitHub to get user info
        """
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        

        response = Response(data, status=status.HTTP_200_OK)

        # response = Response(
        #     {
        #         "message": data["message"],
        #         "username": data["username"],
        #         "email": data["email"],
        #     },
        #     status=status.HTTP_200_OK,
        # )

        response.set_cookie(
            key="access",
            value=data["access"],
            httponly=True,
            max_age=60 * 60,
            path="/",
            secure=True,
            samesite="None",
        )
        response.set_cookie(
            key="refresh",
            value=data["refresh"],
            httponly=True,
            max_age=60 * 60 * 24,
            path="/",
            secure=True,
            samesite="None",
        )

        return response


class XSocialAuthView(APIView):
    permission_classes = []
    authentication_classes = []
    serializer_class = XAuthSerializer

    def post(self, request):
        """
        POST with "code"
        Send authorization code from X (Twitter) to get user info
        """
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        response = Response(
            {
                "message": data["message"],
                "username": data["username"],
                "email": data["email"],
                "access": data["access"],
                "refresh": data["refresh"],
            },
            status=status.HTTP_200_OK,
        )

        response.set_cookie(
            key="access",
            value=data["access"],
            httponly=True,
            max_age=60 * 60,
            path="/",
            secure=True,
            samesite="None",
        )
        response.set_cookie(
            key="refresh",
            value=data["refresh"],
            httponly=True,
            max_age=60 * 60 * 24 * 1,
            path="/",
            secure=True,
            samesite="None",
        )

        return response
