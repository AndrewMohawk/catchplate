FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SERVERWARE_DATA_DIR=/data

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 10001 serverware \
    && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin serverware \
    && mkdir -p /data /anchors \
    && chown -R serverware:serverware /data /anchors /home/serverware

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY serverware ./serverware
COPY scripts ./scripts
COPY schemas ./schemas
COPY policies ./policies
COPY security ./security
COPY docker-compose.apparmor.yml ./docker-compose.apparmor.yml

EXPOSE 3000 8080 8443

USER serverware

CMD ["python", "-m", "serverware.runner"]
