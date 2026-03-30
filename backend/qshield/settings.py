import os
from pathlib import Path
from dotenv import load_dotenv
 
load_dotenv()
 
BASE_DIR   = Path(__file__).resolve().parent.parent
SECRET_KEY = os.environ.get('SECRET_KEY', 'change-me-in-production')
DEBUG      = os.environ.get('DEBUG', 'True') == 'True'
ALLOWED_HOSTS = os.environ.get('ALLOWED_HOSTS', '127.0.0.1,localhost').split(',')
 
# ── Installed Apps ────────────────────────────────────────────────
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    # NOTE: No staticfiles — frontend is served separately by Nginx
    'rest_framework',  # Django REST Framework
    'corsheaders',     # CORS — allows frontend on port 3000 to call us
    'qshield',
]
 
# ── Middleware ───────────────────────────────────────────────────
MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',  # MUST be first
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
]
 
ROOT_URLCONF = 'qshield.urls'
 
# ── NO TEMPLATES for pages — Django renders NO HTML ─────────────
# Frontend HTML lives in frontend/pages/ and runs separately.
# The only exception is Django's built-in admin panel.
TEMPLATES = [{
    'BACKEND': 'django.template.backends.django.DjangoTemplates',
    'DIRS': [],
    'APP_DIRS': True,
    'OPTIONS': {'context_processors': [
        'django.template.context_processors.request',
        'django.contrib.auth.context_processors.auth',
        'django.contrib.messages.context_processors.messages',
    ]},
}]
 
WSGI_APPLICATION = 'qshield.wsgi.application'
 
# ── Database ─────────────────────────────────────────────────────
DATABASE_URL = os.environ.get('DATABASE_URL', '')
if DATABASE_URL.startswith('postgresql'):
    import dj_database_url
    DATABASES = {'default': dj_database_url.parse(DATABASE_URL)}
else:
    DATABASES = {'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME':   BASE_DIR / 'qshield_dev.db',
    }}
 
# ── Django REST Framework ─────────────────────────────────────────
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.SessionAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.UserRateThrottle',
    ],
    'DEFAULT_THROTTLE_RATES': {'user': '200/hour'},
}
 
# ── CORS — allows frontend (port 3000) to call API (port 8000) ───
CORS_ALLOWED_ORIGINS = [
    'http://localhost:3000',
    'http://127.0.0.1:3000',
    'http://localhost:8000',
]
CORS_ALLOW_CREDENTIALS = True  # required for session-based auth
 
# ── Auth ──────────────────────────────────────────────────────────
LOGIN_URL = '/api/login/'
SESSION_COOKIE_AGE      = 3600
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'None'   # required for cross-origin cookie
SESSION_COOKIE_SECURE   = False    # set True in production (HTTPS)
CSRF_COOKIE_SAMESITE    = 'None'
CSRF_TRUSTED_ORIGINS    = ['http://localhost:3000']
 
# ── Production Security ──────────────────────────────────────────
if not DEBUG:
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE    = True
 
LANGUAGE_CODE       = 'en-us'
TIME_ZONE           = 'UTC'
USE_I18N            = True
USE_TZ              = True
DEFAULT_AUTO_FIELD  = 'django.db.models.BigAutoField'