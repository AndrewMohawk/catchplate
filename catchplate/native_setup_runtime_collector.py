"""Fixed operator routing into the existing native proof client, not authority.

The local journal trusts its owner and filesystem. It prevents this command
from dispatching a second collector for the same Setup; it is not hostile-host
custody, global nonce consumption, a native signer or a Setup receipt issuer.
"""
import argparse
import contextlib
import fcntl
import hashlib
import ipaddress
import json
import os
import signal
import stat
import subprocess
import time

from catchplate import authority_setup_native_runtime as p
from catchplate import authority_setup_native_runtime_policy as policy
from catchplate import authority_setup_native_runtime_receipt as receipt


CONFIGURATION = "catchplate.setupNativeRuntimeCollector/v1"
CONFIGURATION_FIELDS = frozenset({"apiVersion", "proofClient", "nativeVerifier", "nativeTrustRoots",
    "nativeIngress", "proxy", "proxyServerName", "proxyCa", "proxyClientCertificate", "proxyClientKey",
    "innerCa", "collectorKey", "controlPlaneResponseKey", "maximumContactSeconds"})
PUBLIC_FILES = {"attemptOriginal": ("attempt.json", 8192), "scopeOriginal": ("scope.json", 32768),
    "expectationsOriginal": ("expectations.json", 16384)}
MAX_BUNDLE = 128 * 1024
CAPTURE = "capture.json"
UNKNOWN = "contact-unknown"


def _need(condition):
    if not condition:
        raise ValueError("collector input or retained ownership refused")


def _sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _identity(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid, metadata.st_gid,
        metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns, metadata.st_nlink)


def _path(path):
    _need(type(path) is str and path.startswith("/") and len(path.encode()) <= 4096
        and all(part not in ("", ".", "..") for part in path.split("/")[1:]) and "\0" not in path)
    return path


@contextlib.contextmanager
def _directory(path, *, private=False):
    """Open each component without symlinks, retaining the final real directory."""
    if path != "/":
        _path(path)
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in (() if path == "/" else path.split("/")[1:]):
            metadata = os.fstat(fd)
            _need(metadata.st_uid in (0, os.geteuid()) and not metadata.st_mode & 0o022)
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd); fd = child
        metadata = os.fstat(fd)
        _need(metadata.st_uid in (0, os.geteuid()) and not metadata.st_mode & 0o022)
        if private:
            _need(metadata.st_uid == os.geteuid() and stat.S_IMODE(metadata.st_mode) == 0o700)
        yield fd
    finally:
        os.close(fd)


def _read_at(directory, name, maximum, *, executable=False):
    fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        before = os.fstat(fd)
        _need(stat.S_ISREG(before.st_mode) and before.st_uid in (0, os.geteuid())
            and not before.st_mode & 0o022 and before.st_nlink == 1 and 0 < before.st_size <= maximum)
        if executable:
            _need(before.st_mode & 0o111 and not before.st_mode & 0o6000)
        parts, left = [], maximum + 1
        while left:
            part = os.read(fd, min(left, 65536))
            if not part:
                break
            parts.append(part); left -= len(part)
        raw = b"".join(parts)
        _need(len(raw) == before.st_size and _identity(os.fstat(fd)) == _identity(before)
            and _identity(os.stat(name, dir_fd=directory, follow_symlinks=False)) == _identity(before))
        return raw
    finally:
        os.close(fd)


def _read(path, maximum, *, pin=None, executable=False):
    _path(path)
    parent, name = path.rsplit("/", 1)
    with _directory(parent or "/") as directory:
        raw = _read_at(directory, name, maximum, executable=executable)
    if pin is not None:
        p.digest(pin); _need(_sha(raw) == pin)
    return raw


def _write_at(directory, name, raw):
    """Exclusive publication only. Even a partial original remains a fence."""
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600, dir_fd=directory)
    try:
        view = memoryview(raw)
        while view:
            count = os.write(fd, view); _need(count > 0); view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(directory)


def _bundle(raw):
    value = receipt.exact(receipt.document(raw, MAX_BUNDLE), PUBLIC_FILES)
    originals = {}
    for field, (_, maximum) in PUBLIC_FILES.items():
        _need(type(value[field]) is str and value[field].isascii())
        original = value[field].encode("ascii")
        document = p.enrollment.setup.document(original, maximum)
        _need(p.canonical(document) == original)
        originals[field] = original
    attempt = p.prepared(value["attemptOriginal"])
    scope = policy.scope(p.enrollment.setup.document(originals["scopeOriginal"], 32768))
    _need(_sha(originals["scopeOriginal"]) == attempt["scopeSha256"])
    policy.attempt_scope(attempt, scope)
    expected = {key: item for key, item in scope["nativeAssignment"].items() if key != "holderId"}
    expected.update(apiVersion="catchplate.nativeResponseAttestationExpectations/v2",
        statementProfile="catchplate.nativeResponseStatements/v1", nonce=attempt["nonce"])
    _need(p.canonical(expected) == originals["expectationsOriginal"])
    return originals, attempt, scope


def _configuration(raw):
    value = receipt.exact(receipt.document(raw, 16384), CONFIGURATION_FIELDS)
    _need(value["apiVersion"] == CONFIGURATION)
    for field in ("proofClient", "nativeVerifier", "nativeTrustRoots", "nativeIngress"):
        item = receipt.exact(value[field], {"path", "sha256"})
        _path(item["path"]); p.digest(item["sha256"])
    for field in ("proxyCa", "proxyClientCertificate", "proxyClientKey", "innerCa", "collectorKey", "controlPlaneResponseKey"):
        _path(value[field])
    endpoint = value["proxy"]
    _need(type(endpoint) is str and len(endpoint) <= 128)
    if endpoint.startswith("["):
        address, port = endpoint[1:].split("]:")
    else:
        address, port = endpoint.rsplit(":", 1)
    ip = ipaddress.ip_address(address)
    _need(not ip.is_unspecified and not ip.is_multicast and "%" not in address
        and str(ip) == address and str(int(port)) == port and 1 <= int(port) <= 65535
        and str(ip) != "255.255.255.255")
    _need(endpoint == (f"[{ip}]:{port}" if ip.version == 6 else f"{ip}:{port}"))
    name = value["proxyServerName"]
    _need(type(name) is str and 0 < len(name) <= 253 and name.isascii() and name == name.strip()
        and not any(ord(char) < 33 or ord(char) > 126 for char in name))
    _need(type(value["maximumContactSeconds"]) is int and 1 <= value["maximumContactSeconds"] <= 120)
    return value


def _capture(raw, attempt, scope):
    """Rejoin the actual signed output; final Nitro/currentness admission is CP-owned."""
    value = receipt.exact(receipt.document(raw, p.MAX_CAPTURE), {"apiVersion", "kind", "resultScope", "okForAction",
        "environment", "captureMode", "external_capture", "runtime_proof", "native_verification", "collector_signature"})
    _need(value["apiVersion"] == "catchplate.nativeResponseCapture/v2"
        and value["kind"] == "CatchplateNativeResponseCapture" and value["captureMode"] == "buffered"
        and value["resultScope"] == "local-capture-and-native-quote-only"
        and value["environment"] == "native-unadmitted" and value["okForAction"] is False)
    receipt.signature(value["collector_signature"], receipt.utf8({key: item for key, item in value.items()
        if key != "collector_signature"}), scope["collectorPublicKeyPem"], capture=True)
    proof = value["runtime_proof"]
    _need(type(proof) is dict and proof.get("apiVersion") == "catchplate.nativeResponseRuntimeProof/v2")
    statement = proof.get("server_statement"); _need(type(statement) is dict)
    for field, expected in {"apiVersion": "catchplate.nativeProxyResponseStatement/v1", "client_nonce": attempt["nonce"],
            "principal_id": attempt["principalId"], "route_id": attempt["routeId"], "policy_digest": attempt["policyHash"],
            "client_request_digest": attempt["clientRequestSha256"], "runtime_manifest_digest": scope["responseRuntimeManifestSha256"],
            "release_digest": scope["responseProvenanceSha256"]}.items():
        _need(statement.get(field) == expected)
    _need(proof.get("server_statement_sha256") == _sha(receipt.utf8(statement)))
    response = statement.get("response")
    _need(type(response) is dict and type(response.get("status")) is int and 200 <= response["status"] <= 299)
    return _sha(raw)


def _slot(attempt):
    # The Setup session, not the output filename or selected executable, chooses
    # the persistent slot. A differently rendered attempt cannot open a retry.
    return hashlib.sha256(b"catchplate/setup-runtime-collector-slot/v1\0"
        + attempt["sessionId"].encode("utf-8")).hexdigest()


def _live(attempt, boottime_deadline):
    now = time.time_ns()
    _need(attempt["issuedAtEpochNs"] <= now < attempt["expiresAtEpochNs"]
        and time.clock_gettime_ns(time.CLOCK_BOOTTIME) < boottime_deadline)


@contextlib.contextmanager
def _executable(raw):
    # Copy the independently pinned actual ELF bytes, never invoke a shell or
    # substitute a path after admission. Packaging/closure admission is separate.
    _need(raw.startswith(b"\x7fELF"))
    fd = os.memfd_create("catchplate-setup-proof-client", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        view = memoryview(raw)
        while view:
            count = os.write(fd, view); _need(count > 0); view = view[count:]
        os.fchmod(fd, 0o500)
        seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
        _need(fcntl.fcntl(fd, fcntl.F_GET_SEALS) == seals)
        yield fd
    finally:
        os.close(fd)


def collect(arguments):
    bundle_raw = _read(arguments.bundle, MAX_BUNDLE, pin=arguments.bundle_sha256)
    originals, attempt, scope = _bundle(bundle_raw)
    config_raw = _read(arguments.configuration, 16384, pin=arguments.configuration_sha256)
    config = _configuration(config_raw)
    now = time.time_ns(); _need(attempt["issuedAtEpochNs"] <= now < attempt["expiresAtEpochNs"])
    boottime_deadline = time.clock_gettime_ns(time.CLOCK_BOOTTIME) + min(
        attempt["expiresAtEpochNs"] - now, config["maximumContactSeconds"] * 1_000_000_000)
    executable = config["proofClient"]
    raw_executable = _read(executable["path"], 64 * 1024 * 1024, pin=executable["sha256"], executable=True)
    with _directory(arguments.state_directory, private=True) as state, _executable(raw_executable) as binary:
        _live(attempt, boottime_deadline)
        name = _slot(attempt)
        # mkdir is the irreversible cross-process/process-restart claim. Never
        # remove it, even if fsync, subsequent preparation or spawn fails.
        os.mkdir(name, 0o700, dir_fd=state); os.fsync(state)
        directory = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=state)
        try:
            metadata = os.fstat(directory)
            _need(metadata.st_uid == os.geteuid() and stat.S_IMODE(metadata.st_mode) == 0o700)
            for field, (filename, _) in PUBLIC_FILES.items():
                _write_at(directory, filename, originals[field])
            _write_at(directory, "bundle.json", bundle_raw)
            _write_at(directory, "configuration-sha256", arguments.configuration_sha256.encode("ascii"))
            destination = arguments.state_directory + "/" + name
            expected_key = policy.ca.key_id(policy.ca._public(scope["collectorPublicKeyPem"]))
            remaining = min(attempt["expiresAtEpochNs"] - time.time_ns(),
                boottime_deadline - time.clock_gettime_ns(time.CLOCK_BOOTTIME))
            seconds = min(120, remaining // 1_000_000_000); _need(seconds >= 1)
            command = ["catchplate-proof-client", "--proxy", config["proxy"], "--proxy-server-name", config["proxyServerName"],
                "--proxy-ca", config["proxyCa"], "--proxy-client-cert", config["proxyClientCertificate"],
                "--proxy-client-key", config["proxyClientKey"], "--ca", config["innerCa"],
                "--collector-key", config["collectorKey"], "--expected-collector-key-id", expected_key,
                "--native-capture-max-bytes", str(p.MAX_CAPTURE), "--control-plane-response-key", config["controlPlaneResponseKey"],
                "--native-verifier", config["nativeVerifier"]["path"], "--native-verifier-sha256", config["nativeVerifier"]["sha256"],
                "--native-trust-roots", config["nativeTrustRoots"]["path"], "--native-trust-roots-sha256", config["nativeTrustRoots"]["sha256"],
                "--native-ingress-configuration", config["nativeIngress"]["path"], "--native-ingress-configuration-sha256", config["nativeIngress"]["sha256"],
                "--native-expectations", destination + "/expectations.json", "--native-expectations-sha256", _sha(originals["expectationsOriginal"]),
                "--method", "GET", "--url", "https://" + scope["clientRequest"]["authority"] + scope["clientRequest"]["path"],
                "--expected-server-instance-id", scope["serverInstanceId"], "--expected-principal-id", attempt["principalId"],
                "--proxy-header", "X-Catchplate-Agent: " + attempt["principalId"], "--nonce", attempt["nonce"],
                "--timeout-seconds", str(seconds), "--max-age-seconds", str(scope["nativeAssignment"]["maxAgeSeconds"]),
                "--out", destination + "/" + CAPTURE]
            _need(_read(arguments.bundle, MAX_BUNDLE, pin=arguments.bundle_sha256) == bundle_raw
                and _read(arguments.configuration, 16384, pin=arguments.configuration_sha256) == config_raw)
            _live(attempt, boottime_deadline)
            _write_at(directory, UNKNOWN, b"Collector spawn may have occurred. No retry or slot removal.\n")
            _live(attempt, boottime_deadline)
            child = None
            try:
                child = subprocess.Popen(command, executable=f"/proc/self/fd/{binary}", pass_fds=(binary,), close_fds=True,
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd="/",
                    env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}, start_new_session=True)
                while True:
                    _live(attempt, boottime_deadline)
                    timeout = min(attempt["expiresAtEpochNs"] - time.time_ns(),
                        boottime_deadline - time.clock_gettime_ns(time.CLOCK_BOOTTIME)) / 1_000_000_000
                    _need(timeout > 0)
                    try:
                        result = child.wait(timeout=min(0.25, timeout))
                        _need(result == 0); break
                    except subprocess.TimeoutExpired:
                        # Observe original wall/BOOTTIME bounds after suspension;
                        # repeated waits never create a new contact allowance.
                        continue
            finally:
                if child is not None and child.poll() is None:
                    # This child owns a fresh session. Kill/reap it, never retry.
                    with contextlib.suppress(ProcessLookupError):
                        os.killpg(child.pid, signal.SIGKILL)
                    child.wait()
            _live(attempt, boottime_deadline)
            capture = _read_at(directory, CAPTURE, p.MAX_CAPTURE)
            digest = _capture(capture, attempt, scope)
            _write_at(directory, "capture-sha256", digest.encode("ascii"))
            return {"status": "capture-retained", "capturePath": destination + "/" + CAPTURE,
                "captureSha256": digest, "okForAction": False, "automaticRetryAllowed": False}
        finally:
            os.close(directory)


def export(arguments):
    """Data-only historical export, including a file published before lost ACK."""
    raw = _read(arguments.bundle, MAX_BUNDLE, pin=arguments.bundle_sha256)
    originals, attempt, scope = _bundle(raw)
    with _directory(arguments.state_directory, private=True) as state:
        directory = os.open(_slot(attempt), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=state)
        try:
            metadata = os.fstat(directory)
            _need(metadata.st_uid == os.geteuid() and stat.S_IMODE(metadata.st_mode) == 0o700)
            _need(_read_at(directory, "bundle.json", MAX_BUNDLE) == raw)
            for field, (filename, maximum) in PUBLIC_FILES.items():
                _need(_read_at(directory, filename, maximum) == originals[field])
            _need(_read_at(directory, UNKNOWN, 256) == b"Collector spawn may have occurred. No retry or slot removal.\n")
            capture = _read_at(directory, CAPTURE, p.MAX_CAPTURE)
            digest = _capture(capture, attempt, scope)
        finally:
            os.close(directory)
    path = _path(arguments.out); parent, filename = path.rsplit("/", 1)
    with _directory(parent or "/", private=True) as destination:
        _write_at(destination, filename, capture)
    return {"status": "capture-original-exported", "capturePath": path, "captureSha256": digest,
        "okForAction": False, "automaticRetryAllowed": False}


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False, description="Route one prepared Setup empty-body GET to the existing native proof client; never retry.",
        epilog="Use the Setup native-runtime portal to prepare/download and import the exact capture. No keys, trust roots, or permission are created. See docs/native-pilot-request-collection.md.")
    commands = parser.add_subparsers(dest="command", required=True)
    for name, description in (("collect", "One collector dispatch under the original attempt; existing local Setup slot always refuses."),
            ("export", "Copy a retained original without network, signing, deadline renewal, or retry authority.")):
        selected = commands.add_parser(name, help=description, description=description, allow_abbrev=False)
        selected.add_argument("--bundle", required=True, help="Absolute exact portal collector-bundle download path.")
        selected.add_argument("--bundle-sha256", required=True, help="Exact digest displayed by the authenticated portal.")
        selected.add_argument("--state-directory", required=True, help="Independently provisioned persistent owner-only mode-0700 directory; never reset per attempt.")
        if name == "collect":
            selected.add_argument("--configuration", required=True, help="Independently supplied fixed collector routing inputs; contains paths, never private-key bytes.")
            selected.add_argument("--configuration-sha256", required=True, help="Independently pinned routing-configuration original SHA-256.")
        else:
            selected.add_argument("--out", required=True, help="New exact capture destination within a private mode-0700 directory; no replacement.")
    arguments = parser.parse_args()
    try:
        result = collect(arguments) if arguments.command == "collect" else export(arguments)
    except (Exception, KeyboardInterrupt):
        # Never echo input/child errors, command arguments, keys or captures.
        parser.exit(1, "Refused or outcome unknown. Keep the persistent Setup slot and originals. Export/read retained state only; do not rerun collect or remove its fence.\n")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
