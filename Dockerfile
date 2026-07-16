FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
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
ARG SERVERWARE_INSTALL_PROTOTYPE_MITMPROXY=0
ARG SERVERWARE_PROTOTYPE_MITMPROXY_VERSION=11.0.2
RUN if [ "$SERVERWARE_INSTALL_PROTOTYPE_MITMPROXY" = "1" ]; then \
        pip install --no-cache-dir "mitmproxy==$SERVERWARE_PROTOTYPE_MITMPROXY_VERSION"; \
    fi

COPY serverware ./serverware
COPY serverware_agent_trust ./serverware_agent_trust
COPY scripts ./scripts
COPY pyproject.toml ./pyproject.toml
COPY schemas ./schemas
COPY policies ./policies
COPY security ./security
COPY docker-compose.apparmor.yml ./docker-compose.apparmor.yml

EXPOSE 3000 8080 8443

USER serverware

CMD ["python", "-m", "serverware.runner"]
