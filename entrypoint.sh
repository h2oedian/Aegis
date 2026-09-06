#!/bin/sh
set -e

if [ "${AEGIS_RUN_MIGRATIONS:-false}" = "true" ]; then
    python manage.py migrate --noinput
fi

exec "$@"
