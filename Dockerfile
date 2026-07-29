FROM --platform=linux/amd64 python:3.11-slim@sha256:db3ff2e1800a8581e2c48a27c3995339d47bdf046da21c7627accd3d51053a93 AS python-base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    SERVERWARE_DATA_DIR=/data

WORKDIR /app

RUN groupadd --gid 10001 serverware \
    && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin serverware \
    && mkdir -p /data /anchors /custody-trust /run/serverware/response-signing-private \
    && chown -R serverware:serverware \
        /data \
        /anchors \
        /custody-trust \
        /run/serverware/response-signing-private \
        /home/serverware

FROM python-base AS production-dependencies

COPY requirements.lock .
RUN python -m pip install --no-cache-dir --require-hashes -r requirements.lock

FROM python-base AS proxy-test-dependencies

COPY requirements.proxy-test.lock .
RUN python -m pip install --no-cache-dir --require-hashes -r requirements.proxy-test.lock

FROM production-dependencies AS production-runtime

COPY serverware ./serverware
COPY serverware_agent_trust ./serverware_agent_trust
COPY scripts ./scripts
COPY pyproject.toml ./pyproject.toml
COPY schemas ./schemas
COPY policies ./policies
COPY security ./security
COPY data-plane/decision-gate-rs/src/main.rs ./data-plane/decision-gate-rs/src/main.rs
COPY docker-compose.apparmor.yml ./docker-compose.apparmor.yml

EXPOSE 3000 8080 8443

HEALTHCHECK --interval=5s --timeout=3s --retries=20 \
    CMD ["python", "-c", "import json,sys,urllib.request; opener=urllib.request.build_opener(urllib.request.ProxyHandler({})); response=opener.open('http://localhost:3000/healthz', timeout=2); body=response.read(65537); sys.exit(0 if response.status == 200 and len(body) <= 65536 and json.loads(body).get('ok') is True else 1)"]

USER serverware

CMD ["python", "-m", "serverware.control_plane_runner"]

FROM proxy-test-dependencies AS coder-proxy-test-runtime

COPY serverware ./serverware
COPY serverware_agent_trust ./serverware_agent_trust
COPY scripts ./scripts
COPY pyproject.toml ./pyproject.toml
COPY schemas ./schemas
COPY policies ./policies
COPY security ./security
COPY data-plane/decision-gate-rs/src/main.rs ./data-plane/decision-gate-rs/src/main.rs

USER serverware

ENTRYPOINT ["python"]

FROM production-dependencies AS coder-production-host-preflight-runtime

COPY . .
RUN mkdir -p /opt/serverware/host-tools

USER serverware

FROM production-runtime AS runtime
