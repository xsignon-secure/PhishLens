#!/bin/sh
# Container entrypoint: bring the schema up to date, then serve.
# Honors $PORT (set by Render and most PaaS); defaults to 8000.
set -e
alembic upgrade head
exec uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8000}" \
  --proxy-headers --forwarded-allow-ips "*"
