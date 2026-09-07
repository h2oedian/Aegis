import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.getenv("DJANGO_SECRET_KEY", "unsafe-development-key")
DEBUG = os.getenv("DJANGO_DEBUG", "false").lower() == "true"
ALLOWED_HOSTS = [
    host.strip()
    for host in os.getenv("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")
    if host.strip()
]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "aegis_core",
    "aegis_rules",
    "aegis_ml",
    "dashboard",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "aegis_core.middleware.RequestTelemetryMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    }
]

WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.getenv("POSTGRES_DB", "aegis"),
        "USER": os.getenv("POSTGRES_USER", "aegis"),
        "PASSWORD": os.getenv("POSTGRES_PASSWORD", "aegis"),
        "HOST": os.getenv("POSTGRES_HOST", "postgres"),
        "PORT": os.getenv("POSTGRES_PORT", "5432"),
    }
}

AUTH_PASSWORD_VALIDATORS = []
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True
STATIC_URL = "static/"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
CELERY_BROKER_URL = REDIS_URL
CELERY_RESULT_BACKEND = REDIS_URL
CELERY_BEAT_SCHEDULE = {
    "consume-request-stream": {
        "task": "aegis_core.tasks.consume_request_stream",
        "schedule": 1.0,
    }
}

AEGIS_REQUEST_STREAM = os.getenv("AEGIS_REQUEST_STREAM", "aegis:requests")
AEGIS_REQUEST_CONSUMER_GROUP = os.getenv(
    "AEGIS_REQUEST_CONSUMER_GROUP", "aegis-request-loggers"
)
AEGIS_REQUEST_STREAM_MAX_LENGTH = int(
    os.getenv("AEGIS_REQUEST_STREAM_MAX_LENGTH", "100000")
)
AEGIS_REQUEST_BATCH_SIZE = int(os.getenv("AEGIS_REQUEST_BATCH_SIZE", "100"))
AEGIS_REQUEST_CLAIM_IDLE_MS = int(
    os.getenv("AEGIS_REQUEST_CLAIM_IDLE_MS", "60000")
)
AEGIS_REDIS_SOCKET_TIMEOUT_SECONDS = float(
    os.getenv("AEGIS_REDIS_SOCKET_TIMEOUT_SECONDS", "0.01")
)

# Forwarded client IPs are trustworthy only behind a correctly configured proxy.
AEGIS_TRUST_PROXY_HEADERS = (
    os.getenv("AEGIS_TRUST_PROXY_HEADERS", "false").lower() == "true"
)

# Token-bucket rate limiting: bucket size/refill at risk score 0, shrinking
# down to the "min" values as the score approaches 100.
AEGIS_RATE_LIMIT_BASE_CAPACITY = float(os.getenv("AEGIS_RATE_LIMIT_BASE_CAPACITY", "60"))
AEGIS_RATE_LIMIT_BASE_REFILL_PER_SECOND = float(
    os.getenv("AEGIS_RATE_LIMIT_BASE_REFILL_PER_SECOND", "1")
)
AEGIS_RATE_LIMIT_MIN_CAPACITY = float(os.getenv("AEGIS_RATE_LIMIT_MIN_CAPACITY", "3"))
AEGIS_RATE_LIMIT_MIN_REFILL_PER_SECOND = float(
    os.getenv("AEGIS_RATE_LIMIT_MIN_REFILL_PER_SECOND", "0.05")
)
