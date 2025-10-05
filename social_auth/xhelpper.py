import twitter
from django.conf import settings
import requests
import base64


class XAuthTokenVerification:
    """Google class to fetch user details from google and return it"""

    @staticmethod
    def validate_x_auth_tokens(access_token_key, access_token_secret):
        """
        validate_x_auth_tokens method return a x user profile
        """

        consumer_api_key = settings.X_API_KEY
        consumer_api_key_secret = settings.X_API_SECRET_KEY

        try:
            api = twitter.Api(
                consumer_key=consumer_api_key,
                consumer_secret=consumer_api_key_secret,
                access_token_key=access_token_key,
                access_token_secret=access_token_secret,
            )
            
            user_profile_info = api.VerifyCredentials(include_email=True)
            return user_profile_info.__dict__
        except Exception as e:
            return None
        
        

class XAuth:
    @staticmethod
    def exchange_code_for_user_data(code):
        try:
            token_url = "https://api.twitter.com/2/oauth2/token"
            redirect_uri = settings.X_REDIRECT_URI
            code_verifier = "challenge"  # نفس اللي استخدمته في authorization step

            # 👇 إعداد الـ Authorization Header بالطريقة الصح
            client_creds = f"{settings.X_CLIENT_ID}:{settings.X_CLIENT_SECRET}"
            b64_client_creds = base64.b64encode(client_creds.encode()).decode()

            headers = {
                "Authorization": f"Basic {b64_client_creds}",
                "Content-Type": "application/x-www-form-urlencoded",
            }

            data = {
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": redirect_uri,
                "code_verifier": code_verifier,
                # "client_id": settings.X_CLIENT_ID,
            }

            token_response = requests.post(token_url, data=data, headers=headers)
            print("🔹 Token response status:", token_response.status_code)
            print("🔹 Token response text:", token_response.text)

            if token_response.status_code != 200:
                return None

            token_json = token_response.json()
            access_token = token_json.get("access_token")

            if not access_token:
                return None

            # 🧠 جلب بيانات المستخدم
            user_info_url = "https://api.twitter.com/2/users/me?user.fields=id,name,username,profile_image_url"
            user_headers = {"Authorization": f"Bearer {access_token}"}
            user_response = requests.get(user_info_url, headers=user_headers)

            print("🔹 User info:", user_response.text)

            if user_response.status_code != 200:
                return None

            user_data = user_response.json().get("data", {})

            return {
                "id": user_data.get("id"),
                "email": f"{user_data.get('username')}@x.com",
                "username": user_data.get("username"),
                "name": user_data.get("name"),
            }

        except Exception as e:
            print("XAuth Error:", str(e))
            return None