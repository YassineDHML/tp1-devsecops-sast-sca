# Image durcie : Python maintenu, utilisateur non-root, serveur WSGI de production.
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DATABASE_PATH=/app/data/notes.db

WORKDIR /app

RUN apt-get update \
 && apt-get install -y --no-install-recommends iputils-ping \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --uid 10001 appuser

# Dependances installees avant le code pour profiter du cache Docker
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY app/ ./app/
RUN mkdir -p /app/data && chown appuser:appuser /app/data

USER appuser
EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/login', timeout=2)" || exit 1

# --preload : init_db() n'est execute qu'une fois avant le fork des workers
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--preload", "--chdir", "app", "app:app"]
