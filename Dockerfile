FROM --platform=linux/amd64 python:3.11-slim@sha256:db3ff2e1800a8581e2c48a27c3995339d47bdf046da21c7627accd3d51053a93 AS python-base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    CATCHPLATE_DATA_DIR=/data

WORKDIR /app

RUN groupadd --gid 10001 catchplate \
    && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin catchplate \
    && mkdir -p /data /anchors /custody-trust /run/catchplate/response-signing-private \
    && chown -R catchplate:catchplate \
        /data \
        /anchors \
        /custody-trust \
        /run/catchplate/response-signing-private \
        /home/catchplate

FROM python-base AS production-dependencies

COPY requirements.lock .
RUN python -m pip install --no-cache-dir --require-hashes -r requirements.lock

FROM python-base AS proxy-test-dependencies

COPY requirements.proxy-test.lock .
RUN python -m pip install --no-cache-dir --require-hashes -r requirements.proxy-test.lock

FROM production-dependencies AS production-runtime

COPY catchplate ./catchplate
COPY catchplate_agent_trust ./catchplate_agent_trust
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

USER catchplate

CMD ["python", "-m", "catchplate.control_plane_runner"]

FROM proxy-test-dependencies AS coder-proxy-test-runtime

COPY catchplate ./catchplate
COPY catchplate_agent_trust ./catchplate_agent_trust
COPY scripts ./scripts
COPY pyproject.toml ./pyproject.toml
COPY schemas ./schemas
COPY policies ./policies
COPY security ./security
COPY data-plane/decision-gate-rs/src/main.rs ./data-plane/decision-gate-rs/src/main.rs

USER catchplate

ENTRYPOINT ["python"]

FROM production-dependencies AS coder-production-host-preflight-runtime

COPY . .
RUN mkdir -p /opt/catchplate/host-tools

USER catchplate

FROM production-runtime AS development-test-runtime

# Engineering checks need Git for clean-source capture and isolated fixture
# repositories. These tools never enter the default or production runtime.
USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends git make \
    && rm -rf /var/lib/apt/lists/*
USER catchplate

FROM development-test-runtime AS development-postgres-test-runtime

# Local SQL engineering tests use a disposable Unix-socket PostgreSQL cluster.
# The server and client tools do not enter the production or default runtime.
USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends postgresql \
    && rm -rf /var/lib/apt/lists/*
USER catchplate
HEALTHCHECK NONE

FROM production-runtime AS runtime
