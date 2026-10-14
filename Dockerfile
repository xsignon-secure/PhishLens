FROM python:3.12-slim

WORKDIR /srv/phishlens
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
# Needed in the image for `alembic upgrade head` on deploy and for the
# scheduled rescan job (`python scripts/rescan.py`), per docs/DEPLOY.md.
COPY alembic ./alembic
COPY alembic.ini .
COPY scripts ./scripts
# Strip Windows (CRLF) line endings in case the files were edited or copied on
# Windows; /bin/sh can't run a script with CRLF endings.
RUN sed -i 's/\r$//' scripts/start.sh

RUN useradd --system --home /srv/phishlens phishlens && chown -R phishlens /srv/phishlens
USER phishlens

ENV PYTHONUNBUFFERED=1
EXPOSE 8000
# scripts/start.sh runs `alembic upgrade head`, then uvicorn on $PORT (default
# 8000) with --proxy-headers: Fly.io/Render/Caddy terminate TLS in front of the
# app, and this makes per-IP rate limits see the real client.
CMD ["sh", "scripts/start.sh"]
