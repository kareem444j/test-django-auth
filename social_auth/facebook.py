import facebook
import requests
from django.conf import settings


class Facebook:
    """ Google class to fetch user details from google and return it """

    @staticmethod
    def validate(auth_token):
        """
        validate method query the google OAuth2 api to fetch the user info
        """
        
        try:
            # Check if the token is valid bg debug_token
            app_access_token = f"{settings.FACEBOOK_APP_ID}|{settings.FACEBOOK_APP_SECRET}"
            debug_url = f"https://graph.facebook.com/debug_token?input_token={auth_token}&access_token={app_access_token}"
            
            debug_response = requests.get(debug_url).json()
            
            if "data" not in debug_response or not debug_response["data"].get("is_valid"):
                return None # Token is invalid
            
            graph = facebook.GraphAPI(access_token=auth_token)
            profile = graph.request('/me?fields=id,name,email')
            return profile
        except Exception as e:
            return None
        
    def exchange_code_for_user_data(code):
        try:
            redirect_uri = settings.FACEBOOK_REDIRECT_URI
            token_url = (
                f"https://graph.facebook.com/v18.0/oauth/access_token"
                f"?client_id={settings.FACEBOOK_APP_ID}"
                f"&redirect_uri={redirect_uri}"
                f"&client_secret={settings.FACEBOOK_APP_SECRET}"
                f"&code={code}"
            )

            token_response = requests.get(token_url).json()
            access_token = token_response.get("access_token")

            if not access_token:
                return None

            graph = facebook.GraphAPI(access_token=access_token)
            profile = graph.request('/me?fields=id,name,email')
            return profile
        except Exception:
            return None