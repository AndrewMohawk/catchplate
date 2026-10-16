# One app/normal-gate artifact. No test binaries, custody services, or runtime builds.
ARG PYTHON_BASE=python:3.11-slim@sha256:db3ff2e1800a8581e2c48a27c3995339d47bdf046da21c7627accd3d51053a93
ARG RUST_BASE=rust:1.88-slim-bookworm@sha256:38bc5a86d998772d4aec2348656ed21438d20fcdce2795b56ca434cf21430d89
ARG CACHED_APP_IMAGE=python:3.11-slim@sha256:db3ff2e1800a8581e2c48a27c3995339d47bdf046da21c7627accd3d51053a93
ARG DEPENDENCY_STAGE=python-dependencies
ARG BINARY_STAGE=normal-build

FROM ${PYTHON_BASE} AS python-dependencies
COPY requirements.lock /requirements.lock
RUN python -m pip install --no-cache-dir --require-hashes -r /requirements.lock

FROM ${CACHED_APP_IMAGE} AS cached-dependencies

FROM ${RUST_BASE} AS normal-build
WORKDIR /src
COPY data-plane/decision-gate-rs ./data-plane/decision-gate-rs
COPY schemas ./schemas
COPY policies ./policies
COPY ops ./ops
COPY scripts/discard_headers_parity.v1.json ./scripts/discard_headers_parity.v1.json
ENV CARGO_BUILD_JOBS=2 RUSTFLAGS="-C link-arg=-Wl,--build-id=none"
RUN --mount=type=cache,id=serverware-standalone-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=serverware-standalone-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=serverware-standalone-normal-target,target=/src/data-plane/decision-gate-rs/target,sharing=locked \
    cargo build --manifest-path data-plane/decision-gate-rs/Cargo.toml --release --locked --bin serverware-decision-gate \
    && install -D -m 0555 data-plane/decision-gate-rs/target/release/serverware-decision-gate /out/serverware-decision-gate

FROM scratch AS cached-binary
COPY artifact/serverware-decision-gate /out/serverware-decision-gate

FROM ${BINARY_STAGE} AS selected-binary

# Cached assembly preserves its verified Python/libc pair. Move its old source
# aside inside the NEW layer; never overlay current source on old /app contents.
# The source-build default has a fresh dependency base and no archived source.
FROM ${DEPENDENCY_STAGE} AS standalone
USER root
ARG SOURCE_REVISION
LABEL org.opencontainers.image.revision=${SOURCE_REVISION} \
    io.serverware.artifact.schema=serverware.standaloneArtifact/v1 \
    io.serverware.artifact.path=/opt/serverware/artifact.json
RUN mkdir -p /opt/serverware \
    && if [ -d /app ]; then test ! -e /opt/serverware/dependency-source \
        && mv /app /opt/serverware/dependency-source; fi \
    && mkdir -p /app
COPY --from=selected-binary /out/serverware-decision-gate /usr/local/bin/serverware-decision-gate
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/app SERVERWARE_DATA_DIR=/data
WORKDIR /app
COPY serverware ./serverware
COPY serverware_agent_trust ./serverware_agent_trust
COPY scripts ./scripts
COPY schemas ./schemas
COPY policies ./policies
COPY security ./security
COPY examples ./examples
COPY pyproject.toml requirements.lock ./
COPY artifact/metadata.json /opt/serverware/metadata.json
RUN python -m scripts.operator_install.image_manifest \
    && if ! getent group serverware >/dev/null; then groupadd --gid 10001 serverware; fi \
    && if ! id serverware >/dev/null 2>&1; then useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin serverware; fi \
    && test "$(id -u serverware)" = 10001 && test "$(id -g serverware)" = 10001
USER 10001:10001
ENTRYPOINT ["python", "-B", "-m", "scripts.operator_install.runtime"]
CMD ["app"]
