from pathlib import Path
from datetime import timedelta
from dotenv import load_dotenv
import os

load_dotenv() # take environment variables from .env if it exists

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-itnqhf+8-np7obz*+*zd2u!0lc0zh2k@%%+y_9in4po)(m*y7n'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ["*"]


# Application definition
INSTALLED_APPS = [
    'corsheaders',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'axes', # django-axes for brute-force attack protection
    'api',
    'users',
    'rest_framework',
    'rest_framework_simplejwt',
    "rest_framework_simplejwt.token_blacklist", # to enable token blacklisting
    "social_auth",
]




MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'axes.middleware.AxesMiddleware', # must be before AuthenticationMiddleware
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    "users.middleware.DoubleSubmitCSRFMiddleware", # custom double-submit CSRF middleware to protect against CSRF attacks
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'backend.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'], # specify your templates directory here
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'backend.wsgi.application'

# Database
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}


# Password validation
# https://docs.djangoproject.com/en/5.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/5.2/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.2/howto/static-files/

STATIC_URL = 'static/'

# Default primary key field type
# https://docs.djangoproject.com/en/5.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


# CORS_ALLOW_ALL_ORIGINS = True # use this to allow all origins if you don't use cookies httpOnly
CORS_ALLOW_CREDENTIALS = True

CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://localhost:8000",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:8000",
]


# REST Framework and JWT settings
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework_simplejwt.authentication.JWTAuthentication",    
        "users.authentication.CookieJWTAuthentication",    
    ),
    "DEFAULT_PERMISSION_CLASSES": (
        "rest_framework.permissions.IsAuthenticated",
    ),
    "EXCEPTION_HANDLER": "users.exceptions.custom_exception_handler", # use custom exception handler if you not use exception_handler
}

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=60),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=1)
    # you can add more settings here if needed
    # ...
}


# axes settings
AXES_FAILURE_LIMIT = 5
AXES_COOLOFF_TIME = 1
AXES_RESET_ON_SUCCESS = True
AXES_LOCKOUT_TEMPLATE = None
AXES_ONLY_USER_FAILURES = True
AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP = True

# email settings
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = "smtp.gmail.com"          
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = "kareem147j@gmail.com"   
EMAIL_HOST_PASSWORD = "dgxdibgesgsjvhfs"
DEFAULT_FROM_EMAIL = EMAIL_HOST_USER

# urls to exempt from double-submit CSRF check
CSRF_EXEMPT_URLS = [
    # "/api/token/", "/api/user/register/"   # optional
]

##############################################################################################
# important for OAuth2
# google auth
GOOGLE_CLIENT_ID = "9424209735-i59dqr7kmkptahe1vtuuhml8057op3bc.apps.googleusercontent.com"
# facebook auth
FACEBOOK_APP_ID = 1951714798729563
FACEBOOK_APP_SECRET = "f2dfff6e7afe906468f547a1efbe8468"
FACEBOOK_REDIRECT_URI = "http://localhost:8000/" # same as in facebook oauth url redirect_uri param
# x auth
X_API_KEY = "ceGaKSsjIKMRTiYExlkEIgViw"
X_API_SECRET_KEY = "kIuNijwP2djHKOwrcB4PDaqgdTYVSVG5T2MZjhI53caYGPFRhS"
X_REDIRECT_URI="http://localhost:5500/"
X_CODE_VERIFIER="challenge"
X_CLIENT_ID="b21PYzA2T0NWTk5wc3NzQkdLVDg6MTpjaQ"
X_CLIENT_SECRET="vhoQjVUIQfqGtJ50wJ6LIlmtD86iwPdkqd_YNg5P_RKLgqG6hA"
# Github auth
GITHUB_CLIENT_ID="Ov23li9W930jKlsOgKPF"
GITHUB_CLIENT_SECRET="abdc646c3a40c11b301c2381b2e561221f213225"
GITHUB_REDIRECT_URI="http://localhost:5500/"
# password for social auth users (OAuth2)
SOCIAL_SECRET_KEY = "4k1zq8z@8z3z$y5v1f3h3v3x8y7z6y5x4w3v2u1t0s9r8q7p6o5n4m3l2k1j0i"
##############################################################################################


# لو عاوز تستخدم طريقة تانيه في عملية الخاشينج للباسورد 
# install: pip install argon2-cffi
# PASSWORD_HASHERS = [
#     "django.contrib.auth.hashers.Argon2PasswordHasher",       # لو حابب Argon2
#     "django.contrib.auth.hashers.PBKDF2PasswordHasher",
#     "django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher",
#     "django.contrib.auth.hashers.BCryptSHA256PasswordHasher",
#     "django.contrib.auth.hashers.ScryptPasswordHasher",
# ]