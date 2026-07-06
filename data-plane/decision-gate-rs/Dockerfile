FROM rust:1.88-slim-bookworm AS build

WORKDIR /src
COPY data-plane/decision-gate-rs/Cargo.toml ./Cargo.toml
COPY data-plane/decision-gate-rs/Cargo.lock ./Cargo.lock
COPY data-plane/decision-gate-rs/src ./src
RUN cargo build --release

FROM debian:bookworm-slim

RUN groupadd --gid 10001 serverware \
    && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin serverware
COPY --from=build /src/target/release/serverware-decision-gate /usr/local/bin/serverware-decision-gate
USER serverware
EXPOSE 9090
ENTRYPOINT ["/usr/local/bin/serverware-decision-gate"]
