import requests

class GitHubAuth:
    TOKEN_URL = "https://github.com/login/oauth/access_token"
    USER_URL = "https://api.github.com/user"
    EMAILS_URL = "https://api.github.com/user/emails"

    @staticmethod
    def exchange_code_for_user_data(code):
        from django.conf import settings

        # Step 1: code to access token
        data = {
            "client_id": settings.GITHUB_CLIENT_ID,
            "client_secret": settings.GITHUB_CLIENT_SECRET,
            "code": code,
            "redirect_uri": settings.GITHUB_REDIRECT_URI
        }

        headers = {"Accept": "application/json"}
        token_res = requests.post(GitHubAuth.TOKEN_URL, data=data, headers=headers)
        token_json = token_res.json()

        access_token = token_json.get("access_token")
        if not access_token:
            return None

        # Step 2: get user info
        headers = {"Authorization": f"token {access_token}"}
        user_res = requests.get(GitHubAuth.USER_URL, headers=headers)
        user_json = user_res.json()

        # Step 3: get user email (sometimes not in main user data)
        email = user_json.get("email")
        if not email:
            emails_res = requests.get(GitHubAuth.EMAILS_URL, headers=headers)
            emails = emails_res.json()
            for e in emails:
                if e.get("primary") and e.get("verified"):
                    email = e.get("email")
                    break

        if not email:
            return None

        return {
            "id": user_json.get("id"),
            "username": user_json.get("login"),
            "email": email,
            "name": user_json.get("name") or user_json.get("login")
        }
