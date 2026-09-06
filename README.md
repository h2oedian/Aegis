# Aegis

Aegis is an adaptive security layer for Django REST APIs. It collects request
telemetry, detects suspicious behaviour, calculates a risk score, and applies
an appropriate response.

## Development stack

- Django and Django REST Framework
- PostgreSQL
- Redis
- Celery

## Start locally

1. Copy `.env.example` to `.env`.
2. Run `docker compose up --build`.
3. Open `http://localhost:8000/api/health/`.

## Request telemetry

`RequestTelemetryMiddleware` stores non-sensitive request metadata in
PostgreSQL: path, method, response status, duration, client IP, user agent,
authenticated user, and token JTI. Request bodies, cookies, credentials, and
raw tokens are deliberately excluded.
