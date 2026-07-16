FROM rust:1.88-slim-bookworm AS build

ARG SOURCE_DATE_EPOCH="0"
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} \
    RUSTFLAGS="-C link-arg=-Wl,--build-id=none"

WORKDIR /src
COPY data-plane/decision-gate-rs/Cargo.toml ./Cargo.toml
COPY data-plane/decision-gate-rs/Cargo.lock ./Cargo.lock
COPY data-plane/decision-gate-rs/src ./src
COPY data-plane/decision-gate-rs/trust ./trust
COPY schemas /schemas
RUN cargo build --release --locked \
    && install -d -m 0700 /runtime-layout/serverware-custody-state \
    && SERVERWARE_CUSTODY_ATTEMPT_LEDGER_DIRECTORY=/runtime-layout/serverware-custody-state \
        /src/target/release/serverware-custody-runtime --initialize-attempt-ledger

FROM debian:bookworm-slim

RUN groupadd --gid 10001 serverware \
    && groupadd --gid 10003 custody-shared \
    && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin serverware \
    && useradd --uid 10002 --gid 10003 --no-create-home --shell /usr/sbin/nologin custody \
    && install -d -o custody -g custody-shared -m 0710 /run/serverware-custody
COPY --from=build /src/target/release/serverware-decision-gate /usr/local/bin/serverware-decision-gate
COPY --from=build /src/target/release/serverware-proof-client /usr/local/bin/serverware-proof-client
COPY --from=build /src/target/release/serverware-response-proof-fixture /usr/local/bin/serverware-response-proof-fixture
COPY --from=build /src/target/release/serverware-custody-runtime /usr/local/bin/serverware-custody-runtime
COPY --from=build --chown=10002:10003 --chmod=0700 /runtime-layout/serverware-custody-state /var/lib/serverware-custody
COPY --from=build --chown=10002:10003 --chmod=0600 /runtime-layout/serverware-custody-state/manifest.json /var/lib/serverware-custody/manifest.json
COPY --from=build --chown=10002:10003 --chmod=0600 /runtime-layout/serverware-custody-state/ledger.lock /var/lib/serverware-custody/ledger.lock
USER serverware
EXPOSE 9090
ENTRYPOINT ["/usr/local/bin/serverware-decision-gate"]
