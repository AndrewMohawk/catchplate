FROM --platform=linux/amd64 rust:1.88-slim-bookworm@sha256:38bc5a86d998772d4aec2348656ed21438d20fcdce2795b56ca434cf21430d89 AS rust-source

ARG SOURCE_DATE_EPOCH="0"
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} \
    RUSTFLAGS="-C link-arg=-Wl,--build-id=none"

WORKDIR /src
COPY data-plane/decision-gate-rs/Cargo.toml ./Cargo.toml
COPY data-plane/decision-gate-rs/Cargo.lock ./Cargo.lock
COPY data-plane/decision-gate-rs/src ./src
COPY data-plane/decision-gate-rs/trust ./trust
COPY schemas /schemas
COPY scripts/discard_headers_parity.v1.json /scripts/discard_headers_parity.v1.json
COPY policies/credential-limits.examples.json /policies/credential-limits.examples.json
COPY ops/policy-custody /policy-custody-assets
COPY ops/systemd/catchplate-policy-custody-sockets.target /policy-custody-assets/systemd/catchplate-policy-custody-sockets.target
COPY ops/systemd/catchplate-policy-custody.target /policy-custody-assets/systemd/catchplate-policy-custody.target
COPY ops/systemd/catchplate-policy-custody@.socket /policy-custody-assets/systemd/catchplate-policy-custody@.socket
COPY ops/systemd/catchplate-policy-custody@.service.in /policy-custody-assets/systemd/catchplate-policy-custody@.service.in
COPY ops/systemd/catchplate-policy-custody@durable-recovery-store.service.d /policy-custody-assets/systemd/catchplate-policy-custody@durable-recovery-store.service.d
COPY ops/systemd/catchplate-policy-custody@cleanup-authorization-consumer.service.d /policy-custody-assets/systemd/catchplate-policy-custody@cleanup-authorization-consumer.service.d
COPY ops/systemd/catchplate-policy-custody@recovery-target-provider.service.d /policy-custody-assets/systemd/catchplate-policy-custody@recovery-target-provider.service.d
COPY ops/systemd/catchplate-policy-custody@current-signature-authority.service.d /policy-custody-assets/systemd/catchplate-policy-custody@current-signature-authority.service.d
COPY ops/systemd/catchplate-policy-custody@bounded-cleanup-helper.service.d /policy-custody-assets/systemd/catchplate-policy-custody@bounded-cleanup-helper.service.d

FROM rust-source AS build

ARG CARGO_BUILD_JOBS=2

RUN set -eu; \
    cargo build --release --locked \
        --bin catchplate-decision-gate \
        --bin catchplate-proof-client \
        --bin catchplate-response-proof-fixture \
        --bin catchplate-custody-runtime \
        --bin catchplate-response-observation-v2-custody \
        --bin catchplate-policy-shadow-custody \
        --bin catchplate-policy-custody-durable-recovery-store \
        --bin catchplate-policy-custody-recovery-target-provider \
        --bin catchplate-policy-custody-current-signature-authority \
        --bin catchplate-policy-custody-cleanup-authorization-consumer \
        --bin catchplate-policy-custody-bounded-cleanup-helper; \
    ledger_directory=/runtime-layout/catchplate-custody-state; \
    ledger_payload='{"activeBindingCount":0,"activeBindingsAccumulator":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","apiVersion":"catchplate.custodyAttemptLedger/v2","commitSequence":0,"maxObservedEpochMs":0,"prunedThroughEpochMs":0}'; \
    install -d -m 0700 "$ledger_directory"; \
    ledger_checksum="$(printf '%s' "$ledger_payload" | sha256sum)"; \
    ledger_checksum="${ledger_checksum%% *}"; \
    test "${#ledger_checksum}" -eq 64; \
    case "$ledger_checksum" in \
        *[!0-9a-f]*) \
            echo "generated custody ledger checksum is not lowercase SHA-256" >&2; \
            exit 2 \
            ;; \
    esac; \
    printf '{"checksum":"sha256:%s","payload":%s}' \
        "$ledger_checksum" "$ledger_payload" > "$ledger_directory/manifest.json"; \
    chmod 0600 "$ledger_directory/manifest.json"; \
    install -m 0600 /dev/null "$ledger_directory/ledger.lock"; \
    test "$(wc -c < "$ledger_directory/ledger.lock")" -eq 0; \
    test "$(wc -c < "$ledger_directory/manifest.json")" -le 1024; \
    find /policy-custody-assets -type d -exec chmod 0555 {} +; \
    find /policy-custody-assets -type f -exec chmod 0444 {} +; \
    find /policy-custody-assets -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +

FROM rust-source AS coder-test-build

ARG CARGO_BUILD_JOBS=2

RUN set -eu; \
    test_target=/cargo-test-target; \
    messages=/tmp/cargo-test-messages.jsonl; \
    test ! -e "$test_target"; \
    install -d -m 0755 "$test_target"; \
    CARGO_TARGET_DIR="$test_target" \
        cargo test --release --locked --no-run --message-format=json-render-diagnostics \
        > "$messages"; \
    test -s "$messages"

FROM --platform=linux/amd64 python:3.11-slim@sha256:db3ff2e1800a8581e2c48a27c3995339d47bdf046da21c7627accd3d51053a93 AS coder-test-collector

COPY --from=coder-test-build /cargo-test-target /cargo-test-target
COPY --from=coder-test-build /tmp/cargo-test-messages.jsonl /tmp/cargo-test-messages.jsonl
RUN python3 - <<'PY'
import hashlib
import json
import os
from pathlib import Path
import stat

MESSAGE_PATH = Path("/tmp/cargo-test-messages.jsonl")
EXPECTED_ROOT = Path("/cargo-test-target/release/deps")
OUTPUT_ROOT = Path("/test-runtime")
HARNESS_ROOT = OUTPUT_ROOT / "harnesses"
MAX_MESSAGE_BYTES = 16 * 1024 * 1024
MAX_MESSAGE_COUNT = 16_384
MAX_MESSAGE_LINE_BYTES = 256 * 1024
MAX_HARNESS_COUNT = 64
MAX_HARNESS_BYTES = 256 * 1024 * 1024
MAX_TOTAL_HARNESS_BYTES = 2 * 1024 * 1024 * 1024
COPY_CHUNK_BYTES = 1024 * 1024
LOWER_NAME_BYTES = frozenset(
    b"abcdefghijklmnopqrstuvwxyz0123456789_-"
)
LOWER_STEM_BYTES = frozenset(
    b"abcdefghijklmnopqrstuvwxyz0123456789_"
)
LOWER_HEX_BYTES = frozenset(b"0123456789abcdef")


def reject_duplicate_keys(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON object key: {key}")
        value[key] = item
    return value


def reject_nonfinite_number(value):
    raise ValueError(f"non-finite JSON number: {value}")


def require_regular(path, label):
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"{label} must be a non-symlink regular file")
    return metadata


def valid_harness_name(name):
    try:
        encoded = name.encode("ascii")
    except UnicodeEncodeError:
        return False
    if not encoded or encoded.startswith(b"-") or any(
        byte not in LOWER_NAME_BYTES for byte in encoded
    ):
        return False
    stem, separator, digest_suffix = encoded.rpartition(b"-")
    return (
        separator == b"-"
        and bool(stem)
        and not stem[:1].isdigit()
        and all(byte in LOWER_STEM_BYTES for byte in stem)
        and len(digest_suffix) == 16
        and all(byte in LOWER_HEX_BYTES for byte in digest_suffix)
    )


message_metadata = require_regular(MESSAGE_PATH, "Cargo JSON message file")
if message_metadata.st_size <= 0 or message_metadata.st_size > MAX_MESSAGE_BYTES:
    raise ValueError("Cargo JSON message file is empty or exceeds its byte bound")
root_metadata = EXPECTED_ROOT.lstat()
if not stat.S_ISDIR(root_metadata.st_mode):
    raise ValueError("isolated Cargo release/deps root is not a directory")
if OUTPUT_ROOT.exists():
    raise ValueError("Rust test output root already exists")

selected = []
selected_paths = set()
selected_names = set()
message_count = 0
with MESSAGE_PATH.open("rb") as messages:
    for raw_line in messages:
        message_count += 1
        if message_count > MAX_MESSAGE_COUNT:
            raise ValueError("Cargo JSON message count exceeds its bound")
        if len(raw_line) > MAX_MESSAGE_LINE_BYTES:
            raise ValueError("Cargo emitted an oversized JSON message")
        if not raw_line.endswith(b"\n"):
            raise ValueError("Cargo JSON message is not newline-terminated")
        try:
            message = json.loads(
                raw_line,
                object_pairs_hook=reject_duplicate_keys,
                parse_constant=reject_nonfinite_number,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            raise ValueError(f"Cargo emitted invalid JSON: {error}") from error
        if not isinstance(message, dict):
            raise ValueError("Cargo JSON message must be an object")
        if message.get("reason") != "compiler-artifact":
            continue
        profile = message.get("profile")
        if not isinstance(profile, dict):
            raise ValueError("Cargo compiler-artifact profile must be an object")
        if "test" not in profile or not isinstance(profile["test"], bool):
            raise ValueError("Cargo compiler-artifact profile.test must be boolean")
        if profile["test"] is not True:
            continue
        if "executable" not in message:
            raise ValueError("Cargo test compiler-artifact has no executable field")
        executable = message.get("executable")
        if executable is None:
            continue
        if not isinstance(executable, str):
            raise ValueError("Cargo test executable path must be a string or null")
        candidate = Path(executable)
        name = candidate.name
        if executable != str(EXPECTED_ROOT / name) or candidate.parent != EXPECTED_ROOT:
            raise ValueError(
                "Cargo-reported test harness is outside the isolated release/deps root"
            )
        if not valid_harness_name(name):
            raise ValueError(f"unexpected Rust test harness name: {name}")
        if executable in selected_paths or name in selected_names:
            raise ValueError(f"duplicate Cargo test harness output: {name}")
        metadata = require_regular(candidate, f"Rust test harness {name}")
        if metadata.st_size <= 0 or metadata.st_size > MAX_HARNESS_BYTES:
            raise ValueError(f"Rust test harness has an invalid size: {name}")
        if metadata.st_mode & 0o111 == 0:
            raise ValueError(f"Rust test harness is not executable: {name}")
        selected_paths.add(executable)
        selected_names.add(name)
        selected.append(
            (name, candidate, metadata.st_dev, metadata.st_ino, metadata.st_size)
        )
        if len(selected) > MAX_HARNESS_COUNT:
            raise ValueError("Cargo test harness count exceeds its bound")

if message_count == 0:
    raise ValueError("Cargo emitted no JSON messages")
if not selected:
    raise ValueError("Cargo reported no executable test harnesses")
if sum(size for _, _, _, _, size in selected) > MAX_TOTAL_HARNESS_BYTES:
    raise ValueError("collected Rust test harness bytes exceed the total bound")

OUTPUT_ROOT.mkdir(mode=0o755)
HARNESS_ROOT.mkdir(mode=0o755)
OUTPUT_ROOT.chmod(0o755)
HARNESS_ROOT.chmod(0o755)
manifest_entries = []
for name, source, expected_device, expected_inode, expected_size in sorted(selected):
    destination = HARNESS_ROOT / name
    source_fd = os.open(
        source,
        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        source_metadata = os.fstat(source_fd)
        if (
            not stat.S_ISREG(source_metadata.st_mode)
            or source_metadata.st_dev != expected_device
            or source_metadata.st_ino != expected_inode
            or source_metadata.st_size != expected_size
            or source_metadata.st_mode & 0o111 == 0
        ):
            raise ValueError(f"Rust test harness changed before copy: {name}")
        destination_fd = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            0o555,
        )
        digest = hashlib.sha256()
        copied = 0
        try:
            while True:
                chunk = os.read(source_fd, COPY_CHUNK_BYTES)
                if not chunk:
                    break
                copied += len(chunk)
                if copied > expected_size:
                    raise ValueError(f"Rust test harness grew during copy: {name}")
                digest.update(chunk)
                view = memoryview(chunk)
                while view:
                    written = os.write(destination_fd, view)
                    if written <= 0:
                        raise OSError(f"short write while copying {name}")
                    view = view[written:]
            if copied != expected_size:
                raise ValueError(f"Rust test harness shrank during copy: {name}")
            os.fchmod(destination_fd, 0o555)
            os.fsync(destination_fd)
        finally:
            os.close(destination_fd)
    finally:
        os.close(source_fd)
    installed_digest = hashlib.sha256()
    with destination.open("rb") as installed:
        for chunk in iter(lambda: installed.read(COPY_CHUNK_BYTES), b""):
            installed_digest.update(chunk)
    installed_metadata = require_regular(destination, f"installed Rust harness {name}")
    if installed_metadata.st_size != expected_size or installed_metadata.st_mode & 0o777 != 0o555:
        raise ValueError(f"installed Rust test harness metadata is invalid: {name}")
    digest_hex = digest.hexdigest()
    if (
        len(digest_hex) != 64
        or any(byte not in LOWER_HEX_BYTES for byte in digest_hex.encode("ascii"))
        or installed_digest.hexdigest() != digest_hex
    ):
        raise ValueError(f"Rust test harness digest verification failed: {name}")
    manifest_entries.append(f"{digest_hex}  {name}\n")

manifest_path = OUTPUT_ROOT / "SHA256SUMS"
manifest_fd = os.open(
    manifest_path,
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
    0o444,
)
try:
    manifest_bytes = "".join(manifest_entries).encode("ascii")
    view = memoryview(manifest_bytes)
    while view:
        written = os.write(manifest_fd, view)
        if written <= 0:
            raise OSError("short write while creating Rust harness manifest")
        view = view[written:]
    os.fchmod(manifest_fd, 0o444)
    os.fsync(manifest_fd)
finally:
    os.close(manifest_fd)
if len(manifest_entries) != len(selected_names):
    raise ValueError("Rust harness manifest count does not match selected artifacts")
PY
COPY --chmod=0555 data-plane/decision-gate-rs/coder-test-runner.sh /test-runtime/coder-test-runner

FROM --platform=linux/amd64 debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818 AS coder-test-runtime

ENV HOME=/tmp \
    TMPDIR=/tmp \
    PATH=/usr/bin:/bin
COPY --from=coder-test-collector --chown=65532:65532 /test-runtime /opt/catchplate-rust-tests
RUN ! command -v cargo >/dev/null 2>&1 \
    && ! command -v rustc >/dev/null 2>&1 \
    && test ! -e /src \
    && test ! -e /usr/local/cargo \
    && test ! -e /cargo-test-target \
    && test ! -e /tmp/cargo-test-messages.jsonl
USER 65532:65532
ENTRYPOINT ["/opt/catchplate-rust-tests/coder-test-runner"]

FROM --platform=linux/amd64 debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818 AS runtime

RUN groupadd --gid 10001 catchplate \
    && groupadd --gid 10003 custody-shared \
    && groupadd --gid 65519 response-v2-shared \
    && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin catchplate \
    && useradd --uid 10002 --gid 10003 --no-create-home --shell /usr/sbin/nologin custody \
    && useradd --uid 65520 --gid 65519 --no-create-home --shell /usr/sbin/nologin response-v2-router \
    && useradd --uid 65521 --gid 65519 --no-create-home --shell /usr/sbin/nologin response-v2-state \
    && useradd --uid 65522 --gid 65519 --no-create-home --shell /usr/sbin/nologin response-v2-transport \
    && useradd --uid 65523 --gid 65519 --no-create-home --shell /usr/sbin/nologin response-v2-policy \
    && useradd --uid 65524 --gid 65519 --no-create-home --shell /usr/sbin/nologin response-v2-ledger \
    && useradd --uid 65525 --gid 65519 --no-create-home --shell /usr/sbin/nologin response-v2-release \
    && useradd --uid 65526 --gid 65519 --no-create-home --shell /usr/sbin/nologin response-v2-watchdog \
    && install -d -o custody -g custody-shared -m 0710 /run/catchplate-custody \
    && install -d -o response-v2-router -g response-v2-shared -m 0710 /run/catchplate-response-v2/router \
    && install -d -o response-v2-state -g response-v2-shared -m 0710 /run/catchplate-response-v2/state \
    && install -d -o response-v2-transport -g response-v2-shared -m 0710 /run/catchplate-response-v2/credential-transport \
    && install -d -o response-v2-policy -g response-v2-shared -m 0710 /run/catchplate-response-v2/policy-proof-verifier \
    && install -d -o response-v2-ledger -g response-v2-shared -m 0710 /run/catchplate-response-v2/immutable-artifact-ledger \
    && install -d -o response-v2-release -g response-v2-shared -m 0710 /run/catchplate-response-v2/release-attestor-publisher \
    && install -d -o response-v2-watchdog -g response-v2-shared -m 0710 /run/catchplate-response-v2/cleanup-watchdog \
    && install -d -o response-v2-router -g response-v2-shared -m 0700 /var/lib/catchplate-response-v2/custody-router \
    && install -d -o response-v2-state -g response-v2-shared -m 0700 /var/lib/catchplate-response-v2/state-authority \
    && install -d -o response-v2-transport -g response-v2-shared -m 0700 /var/lib/catchplate-response-v2/credential-transport \
    && install -d -o response-v2-policy -g response-v2-shared -m 0700 /var/lib/catchplate-response-v2/policy-proof-verifier \
    && install -d -o response-v2-ledger -g response-v2-shared -m 0700 /var/lib/catchplate-response-v2/immutable-artifact-ledger \
    && install -d -o response-v2-release -g response-v2-shared -m 0700 /var/lib/catchplate-response-v2/release-attestor-publisher \
    && install -d -o response-v2-watchdog -g response-v2-shared -m 0700 /var/lib/catchplate-response-v2/cleanup-watchdog
COPY --from=build /src/target/release/catchplate-decision-gate /usr/local/bin/catchplate-decision-gate
COPY --from=build /src/target/release/catchplate-proof-client /usr/local/bin/catchplate-proof-client
COPY --from=build /src/target/release/catchplate-response-proof-fixture /usr/local/bin/catchplate-response-proof-fixture
COPY --from=build /src/target/release/catchplate-custody-runtime /usr/local/bin/catchplate-custody-runtime
COPY --from=build /src/target/release/catchplate-response-observation-v2-custody /usr/local/bin/catchplate-response-observation-v2-custody
COPY --from=build /src/target/release/catchplate-policy-shadow-custody /usr/local/bin/catchplate-policy-shadow-custody
COPY --from=build /src/target/release/catchplate-policy-custody-durable-recovery-store /usr/local/bin/catchplate-policy-custody-durable-recovery-store
COPY --from=build /src/target/release/catchplate-policy-custody-recovery-target-provider /usr/local/bin/catchplate-policy-custody-recovery-target-provider
COPY --from=build /src/target/release/catchplate-policy-custody-current-signature-authority /usr/local/bin/catchplate-policy-custody-current-signature-authority
COPY --from=build /src/target/release/catchplate-policy-custody-cleanup-authorization-consumer /usr/local/bin/catchplate-policy-custody-cleanup-authorization-consumer
COPY --from=build /src/target/release/catchplate-policy-custody-bounded-cleanup-helper /usr/local/bin/catchplate-policy-custody-bounded-cleanup-helper
COPY --from=build --chown=0:0 /policy-custody-assets /usr/share/catchplate/policy-custody
COPY --from=build --chown=10002:10003 --chmod=0700 /runtime-layout/catchplate-custody-state /var/lib/catchplate-custody
COPY --from=build --chown=10002:10003 --chmod=0600 /runtime-layout/catchplate-custody-state/manifest.json /var/lib/catchplate-custody/manifest.json
COPY --from=build --chown=10002:10003 --chmod=0600 /runtime-layout/catchplate-custody-state/ledger.lock /var/lib/catchplate-custody/ledger.lock
USER catchplate
EXPOSE 9090
ENTRYPOINT ["/usr/local/bin/catchplate-decision-gate"]
