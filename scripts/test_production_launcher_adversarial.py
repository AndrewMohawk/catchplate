#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CRATE = ROOT / "data-plane/decision-gate-rs"
PRODUCTION_TRUST = CRATE / "trust/launch-authority-root.ed25519.hex"
GENERATOR = ROOT / "scripts/generate_production_launch_manifest.py"
PLATFORM = "linux/amd64"

SOURCE_TREE_DIGEST = "sha256:" + "a" * 64
PROVENANCE_DIGEST = "sha256:" + "b" * 64
DEPLOYMENT_IDENTITY_DIGEST = "sha256:" + "c" * 64
DEPLOYMENT_AUDIENCE = "prod.us-east-1.primary"
RELEASE_SEQUENCE = 42
ROLLBACK_EPOCH = 7

ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")

INPUTS = (
    ("production-images-build", "productionImagesBuild"),
    ("production-images-env", "productionImagesEnv"),
    ("production-images-published", "productionImagesPublished"),
    ("release-provenance-summary", "releaseProvenanceSummary"),
    ("release-provenance", "releaseProvenance"),
    ("image-signatures-summary", "imageSignaturesSummary"),
    ("image-signatures", "imageSignatures"),
    ("bench", "bench"),
    ("kms-materials", "kmsMaterials"),
    ("policy-bundle", "policyBundle"),
    ("policy-trusted-public-key", "policyTrustedPublicKey"),
    ("policy-identity-verification", "policyIdentityVerification"),
    ("policy-activation-verification", "policyActivationVerification"),
    ("policy-activation-signature", "policyActivationSignature"),
    ("policy-activation-trusted-public-key", "policyActivationTrustedPublicKey"),
    ("reproducible-build-verification", "reproducibleBuildVerification"),
    ("reproducible-build-signature", "reproducibleBuildSignature"),
    ("reproducible-build-trusted-public-key", "reproducibleBuildTrustedPublicKey"),
)

OUTPUTS = (
    ("config-out", "config.json"),
    ("claims-file", "claims.json"),
    ("nitro-evidence-out", "nitro.json"),
    ("readiness-out", "readiness.json"),
    ("completion-proof-out", "completion.json"),
    ("proxy-proof-summary-out", "proxy.json"),
    ("production-host-preflight", "host-preflight.json"),
)

CHILD_COMMON = r'''
import base64
import fcntl
import hashlib
import json
import os
import time

STATE = "/var/lib/serverware/production-proof"
COMMITTED_NAMES = [
    "LANG",
    "LC_ALL",
    "PATH",
    "SERVERWARE_BOOTSTRAP_RECEIPT_API_VERSION",
    "SERVERWARE_BOOTSTRAP_RECEIPT_FD",
    "SERVERWARE_BOOTSTRAP_RECEIPT_SHA256",
    "TZ",
]
REQUEST_DOMAIN = b"serverware.launchAuthorizationRequest/v1\0"
EXPECTED_AUTHORITY_KEY_ID = "__AUTHORITY_KEY_ID__"


def canonical(value):
    return json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def digest(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def validate_child(phase):
    with open(STATE + "/" + phase + "-python-started", "w", encoding="ascii") as output:
        output.write("started\n")
    assert os.getcwd() == "/opt/serverware/release"
    assert os.environ["LANG"] == "C.UTF-8"
    assert os.environ["LC_ALL"] == "C.UTF-8"
    assert os.environ["PATH"] == "/usr/sbin:/usr/bin:/sbin:/bin"
    assert os.environ["TZ"] == "UTC"
    assert os.environ["SERVERWARE_BOOTSTRAP_RECEIPT_API_VERSION"] == "serverware.bootstrapReceipt/v2"
    assert sorted(os.environ) == sorted(
        COMMITTED_NAMES + ["SERVERWARE_EXECUTING_SCRIPT_FD"]
    )
    for name in ("LD_PRELOAD", "LD_AUDIT", "PYTHONPATH", "PYTHONHOME"):
        assert name not in os.environ

    if os.path.exists(STATE + "/expect-inherited-fd9-closed"):
        try:
            os.fstat(9)
        except OSError as error:
            assert error.errno == 9
        else:
            raise AssertionError("inherited descriptor 9 reached the Python child")

    receipt_fd = int(os.environ["SERVERWARE_BOOTSTRAP_RECEIPT_FD"])
    assert receipt_fd == 198
    metadata = os.fstat(receipt_fd)
    assert metadata.st_size > 0
    required_seals = (
        fcntl.F_SEAL_WRITE
        | fcntl.F_SEAL_GROW
        | fcntl.F_SEAL_SHRINK
        | fcntl.F_SEAL_SEAL
    )
    assert fcntl.fcntl(receipt_fd, fcntl.F_GET_SEALS) & required_seals == required_seals
    os.lseek(receipt_fd, 0, os.SEEK_SET)
    receipt_bytes = b""
    while len(receipt_bytes) < metadata.st_size:
        receipt_bytes += os.read(receipt_fd, metadata.st_size - len(receipt_bytes))
    assert len(receipt_bytes) == metadata.st_size
    assert digest(receipt_bytes) == os.environ["SERVERWARE_BOOTSTRAP_RECEIPT_SHA256"]

    receipt = json.loads(receipt_bytes.decode("utf-8"))
    assert canonical(receipt) == receipt_bytes
    assert receipt["apiVersion"] == "serverware.bootstrapReceipt/v2"
    assert receipt["kind"] == "ProductionBootstrapReceipt"
    assert receipt["sourceTreeDigest"] == "sha256:" + "a" * 64
    assert len(receipt["launchId"]) == 64
    int(receipt["launchId"], 16)
    assert receipt["bootIdSha256"].startswith("sha256:")
    with open("/etc/serverware/production-release-launch.json", "rb") as source:
        assert receipt["manifest"]["sha256"] == digest(source.read())
    assert [root["path"] for root in receipt["python"]["importRoots"]] == [
        "/opt/serverware/release",
        "/opt/serverware/release/runtime/python/lib/python3.11",
        "/opt/serverware/release/runtime/python/lib/python3.11/lib-dynload",
        "/opt/serverware/release/vendor",
    ]
    for name in ("preflightSha256", "readinessSha256"):
        assert len(receipt["argv"][name]) == 71
        assert receipt["argv"][name].startswith("sha256:")

    authorization = receipt["launchAuthorization"]
    request = authorization["request"]
    envelope = authorization["envelope"]
    statement = envelope["statement"]
    request_sha256 = digest(REQUEST_DOMAIN + canonical(request))
    assert authorization["requestSha256"] == request_sha256
    assert statement["requestSha256"] == request_sha256
    assert authorization["authorizationSha256"] == digest(canonical(envelope))
    assert request == {
        "apiVersion": "serverware.launchAuthorizationRequest/v1",
        "kind": "ProductionLaunchAuthorizationRequest",
        "launcherNonce": receipt["launchId"],
        "bootIdSha256": receipt["bootIdSha256"],
        "launcherSha256": receipt["launcher"]["sha256"],
        "manifestSha256": receipt["manifest"]["sha256"],
        "releaseProvenanceSha256": receipt["inputs"]["releaseProvenance"]["sha256"],
        "provenanceDigest": "sha256:" + "b" * 64,
        "reproducibleBuildVerificationSha256": receipt["inputs"]["reproducibleBuildVerification"]["sha256"],
        "sourceTreeDigest": receipt["sourceTreeDigest"],
        "deploymentAudience": "prod.us-east-1.primary",
        "deploymentIdentitySha256": "sha256:" + "c" * 64,
        "releaseSequence": 42,
        "rollbackEpoch": 7,
    }
    assert envelope["apiVersion"] == "serverware.launchAuthorization/v1"
    assert envelope["kind"] == "ProductionLaunchAuthorization"
    assert len(statement["authorizationId"]) == 64
    int(statement["authorizationId"], 16)
    assert statement["authorityKeyId"] == EXPECTED_AUTHORITY_KEY_ID
    assert statement["useLimit"] == 1
    assert statement["expiresAtUnixSeconds"] - statement["issuedAtUnixSeconds"] <= 30
    assert statement["issuedAtUnixSeconds"] <= authorization["verifiedAtUnixSeconds"]
    assert authorization["verifiedAtUnixSeconds"] < statement["expiresAtUnixSeconds"]
    assert "=" not in envelope["signature"]
    signature = base64.urlsafe_b64decode(envelope["signature"] + "==")
    assert len(signature) == 64

    script_fd = int(os.environ["SERVERWARE_EXECUTING_SCRIPT_FD"])
    assert script_fd != receipt_fd
    script_metadata = os.fstat(script_fd)
    assert fcntl.fcntl(script_fd, fcntl.F_GET_SEALS) & required_seals == required_seals
    os.lseek(script_fd, 0, os.SEEK_SET)
    script_bytes = b""
    while len(script_bytes) < script_metadata.st_size:
        script_bytes += os.read(script_fd, script_metadata.st_size - len(script_bytes))
    script_name = "preflight" if phase == "preflight" else "runner"
    script_receipt = receipt["scripts"][script_name]
    assert digest(script_bytes) == script_receipt["sha256"]
    source_metadata = os.stat(script_receipt["path"], follow_symlinks=False)
    assert (script_metadata.st_dev, script_metadata.st_ino) != (
        source_metadata.st_dev,
        source_metadata.st_ino,
    )
    try:
        os.write(script_fd, b"not mutable")
    except OSError as error:
        assert error.errno == 1
    else:
        raise AssertionError("sealed script snapshot accepted a write")

    committed = {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "SERVERWARE_BOOTSTRAP_RECEIPT_API_VERSION": "serverware.bootstrapReceipt/v2",
        "SERVERWARE_BOOTSTRAP_RECEIPT_FD": "198",
        "SERVERWARE_BOOTSTRAP_RECEIPT_SHA256": "sha256:<bootstrap-receipt>",
        "TZ": "UTC",
    }
    assert receipt["environment"] == {
        "names": COMMITTED_NAMES,
        "sha256": digest(canonical(committed)),
    }
    try:
        os.write(receipt_fd, b"not mutable")
    except OSError as error:
        assert error.errno == 1
    else:
        raise AssertionError("sealed receipt accepted a write")

    assert not os.path.exists(STATE + "/hostile-loader-ran")
    assert not os.path.exists(STATE + "/hostile-site-ran")
    with open(STATE + "/" + phase + "-receipt-ok", "w", encoding="ascii") as output:
        output.write(os.environ["SERVERWARE_BOOTSTRAP_RECEIPT_SHA256"] + "\n")
'''

PREFLIGHT = CHILD_COMMON + r'''
validate_child("preflight")
with open(STATE + "/preflight-ran", "w", encoding="ascii") as output:
    output.write("preflight\n")
if os.path.exists(STATE + "/mutate-readiness-source"):
    runner_path = "/opt/serverware/release/scripts/runner.py"
    before = os.stat(runner_path, follow_symlinks=False)
    hostile = (
        b"open('/var/lib/serverware/production-proof/mutated-readiness-ran', 'w').write('bad\\n')\n"
        b"raise SystemExit(91)\n"
    )
    with open(runner_path, "r+b", buffering=0) as target:
        target.write(hostile)
        target.truncate()
    after = os.stat(runner_path, follow_symlinks=False)
    assert (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino)
    with open(STATE + "/readiness-source-mutated", "w", encoding="ascii") as output:
        output.write("same inode\n")
if os.path.exists(STATE + "/force-preflight-fail"):
    raise SystemExit(23)
if os.path.exists(STATE + "/delay-preflight-until-authorization-expires"):
    time.sleep(3.2)
'''

RUNNER = CHILD_COMMON + r'''
validate_child("readiness")
with open(STATE + "/preflight-ran", "r", encoding="ascii") as source:
    assert source.read() == "preflight\n"
with open(STATE + "/readiness-ran", "w", encoding="ascii") as output:
    output.write("readiness\n")
'''

HOSTILE_C = r'''
#include <fcntl.h>
#include <unistd.h>

static void mark_loaded(void) __attribute__((constructor));
static void mark_loaded(void) {
    const char marker[] = "hostile loader executed\n";
    int fd = open(
        "/var/lib/serverware/production-proof/hostile-loader-ran",
        O_WRONLY | O_CREAT | O_APPEND,
        0600
    );
    if (fd >= 0) {
        (void)write(fd, marker, sizeof(marker) - 1);
        (void)close(fd);
    }
}
unsigned int la_version(unsigned int version) { return version; }
'''

AUTHORITY_FIXTURE = r'''
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path


SOCKET = Path("/run/serverware/launch-authority.sock")
LAUNCHER = Path("/opt/serverware/bin/serverware-production-launcher-test")
LAUNCHER_BACKUP = LAUNCHER.with_name(LAUNCHER.name + ".authority-original")
MANIFEST = Path("/etc/serverware/production-release-launch.json")
STATE = Path("/var/lib/serverware/production-proof")
REPLAY = STATE / "replay-authorization-envelope.json"
PRIVATE_KEY = Path("/etc/serverware/test-launch-authority-private.pem")
WRONG_PRIVATE_KEY = Path("/etc/serverware/test-launch-authority-wrong-private.pem")
PUBLIC_KEY_HEX = "__PUBLIC_KEY_HEX__"
SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
REQUEST_DOMAIN = b"serverware.launchAuthorizationRequest/v1\0"
AUTHORIZATION_DOMAIN = b"serverware.launchAuthorization/v1\0"
REQUEST_FIELDS = {
    "apiVersion",
    "kind",
    "launcherNonce",
    "bootIdSha256",
    "launcherSha256",
    "manifestSha256",
    "releaseProvenanceSha256",
    "provenanceDigest",
    "reproducibleBuildVerificationSha256",
    "sourceTreeDigest",
    "deploymentAudience",
    "deploymentIdentitySha256",
    "releaseSequence",
    "rollbackEpoch",
}
DIGEST_FIELDS = {
    "bootIdSha256",
    "launcherSha256",
    "manifestSha256",
    "releaseProvenanceSha256",
    "provenanceDigest",
    "reproducibleBuildVerificationSha256",
    "sourceTreeDigest",
    "deploymentIdentitySha256",
}
BINDING_MUTATIONS = {
    "bind-manifest": "manifestSha256",
    "bind-release-provenance": "releaseProvenanceSha256",
    "bind-provenance-digest": "provenanceDigest",
    "bind-source-tree": "sourceTreeDigest",
    "bind-launcher": "launcherSha256",
    "bind-reproducible-build": "reproducibleBuildVerificationSha256",
    "bind-release-sequence": "releaseSequence",
    "bind-rollback-epoch": "rollbackEpoch",
}
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z", re.ASCII)
HEX_RE = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
AUDIENCE_RE = re.compile(r"[a-z0-9][a-z0-9._:-]{0,127}\Z", re.ASCII)
MAX_SAFE_INTEGER = (1 << 53) - 1


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def canonical(value):
    return json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii")


def digest(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def file_digest(path):
    return digest(path.read_bytes())


def request_digest(request):
    return digest(REQUEST_DOMAIN + canonical(request))


def authority_key_id():
    public = bytes.fromhex(PUBLIC_KEY_HEX)
    require(len(public) == 32, "test authority public key has the wrong length")
    return digest(SPKI_PREFIX + public)


def validate_request(raw):
    require(raw, "launcher sent an empty authorization request")
    require(len(raw) <= 16 * 1024, "launcher sent an oversized authorization request")
    request = json.loads(raw.decode("utf-8"))
    require(type(request) is dict, "authorization request is not an object")
    require(canonical(request) == raw, "authorization request is not canonical JSON")
    require(set(request) == REQUEST_FIELDS, "authorization request fields are not closed")
    require(
        request["apiVersion"] == "serverware.launchAuthorizationRequest/v1",
        "authorization request apiVersion is wrong",
    )
    require(
        request["kind"] == "ProductionLaunchAuthorizationRequest",
        "authorization request kind is wrong",
    )
    require(type(request["launcherNonce"]) is str and HEX_RE.fullmatch(request["launcherNonce"]), "launcher nonce is invalid")
    for field in DIGEST_FIELDS:
        require(type(request[field]) is str and DIGEST_RE.fullmatch(request[field]), field + " is invalid")
    require(
        type(request["deploymentAudience"]) is str
        and AUDIENCE_RE.fullmatch(request["deploymentAudience"]),
        "deployment audience is invalid",
    )
    require(
        type(request["releaseSequence"]) is int
        and 1 <= request["releaseSequence"] <= MAX_SAFE_INTEGER,
        "release sequence is invalid",
    )
    require(
        type(request["rollbackEpoch"]) is int
        and 0 <= request["rollbackEpoch"] <= MAX_SAFE_INTEGER,
        "rollback epoch is invalid",
    )

    manifest_raw = MANIFEST.read_bytes()
    manifest = json.loads(manifest_raw.decode("utf-8"))
    provenance_path = Path(manifest["inputs"]["releaseProvenance"]["path"])
    reproducible_path = Path(manifest["inputs"]["reproducibleBuildVerification"]["path"])
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    expected = {
        "launcherSha256": file_digest(LAUNCHER),
        "manifestSha256": digest(manifest_raw),
        "releaseProvenanceSha256": file_digest(provenance_path),
        "provenanceDigest": provenance["provenance_digest"],
        "reproducibleBuildVerificationSha256": file_digest(reproducible_path),
        "sourceTreeDigest": manifest["sourceTreeDigest"],
        "deploymentAudience": manifest["authorization"]["deploymentAudience"],
        "deploymentIdentitySha256": manifest["authorization"]["deploymentIdentitySha256"],
        "releaseSequence": manifest["authorization"]["releaseSequence"],
        "rollbackEpoch": manifest["authorization"]["rollbackEpoch"],
    }
    require(
        provenance["provenance"]["source_tree"]["digest"] == manifest["sourceTreeDigest"],
        "release provenance source tree does not match the manifest",
    )
    for field, value in expected.items():
        require(request[field] == value, field + " is not bound to the measured fixture")
    return request, manifest


def sign(payload, key_path):
    with tempfile.NamedTemporaryFile(dir=SOCKET.parent) as signing_input:
        signing_input.write(payload)
        signing_input.flush()
        result = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                str(key_path),
                "-in",
                signing_input.name,
            ],
            capture_output=True,
            check=False,
        )
    require(result.returncode == 0, "OpenSSL signing failed: " + result.stderr.decode("utf-8", errors="replace"))
    require(len(result.stdout) == 64, "OpenSSL returned a non-Ed25519 signature")
    return base64.urlsafe_b64encode(result.stdout).rstrip(b"=").decode("ascii")


def build_envelope(request, mode):
    now = int(time.time())
    issued = now - 1
    expires = now + 29
    if mode == "expired":
        issued = now - 21
        expires = now - 1
    elif mode == "future":
        issued = now + 6
        expires = now + 26
    elif mode == "overlong":
        issued = now - 1
        expires = issued + 31
    elif mode == "expires-during-preflight":
        expires = now + 3

    bound_request = request
    if mode in BINDING_MUTATIONS:
        field = BINDING_MUTATIONS[mode]
        bound_request = dict(request)
        if field in ("releaseSequence", "rollbackEpoch"):
            bound_request[field] += 1
        else:
            bound_request[field] = "sha256:" + "f" * 64
    request_sha256 = request_digest(bound_request)
    if mode == "wrong-request-digest":
        request_sha256 = "sha256:" + "0" * 64

    statement = {
        "authorizationId": hashlib.sha256(canonical(request) + str(time.time_ns()).encode("ascii")).hexdigest(),
        "authorityKeyId": authority_key_id(),
        "requestSha256": request_sha256,
        "issuedAtUnixSeconds": issued,
        "expiresAtUnixSeconds": expires,
        "useLimit": 1,
    }
    signed = {
        "apiVersion": "serverware.launchAuthorization/v1",
        "kind": "ProductionLaunchAuthorization",
        "statement": statement,
    }
    key_path = WRONG_PRIVATE_KEY if mode == "wrong-signing-key" else PRIVATE_KEY
    return canonical({**signed, "signature": sign(AUTHORIZATION_DOMAIN + canonical(signed), key_path)})


def append_mutation(path):
    with path.open("ab", buffering=0) as target:
        target.write(b" ")
    (STATE / "post-auth-mutation-applied").write_text(str(path) + "\n", encoding="ascii")


def mutate_after_request(mode, manifest):
    if mode == "post-auth-manifest-mutation":
        append_mutation(MANIFEST)
    elif mode == "post-auth-provenance-mutation":
        append_mutation(Path(manifest["inputs"]["releaseProvenance"]["path"]))
    elif mode == "post-auth-repro-mutation":
        append_mutation(Path(manifest["inputs"]["reproducibleBuildVerification"]["path"]))
    elif mode == "post-auth-preflight-mutation":
        append_mutation(Path(manifest["scripts"]["preflight"]["path"]))
    elif mode == "post-auth-launcher-mutation":
        require(not LAUNCHER_BACKUP.exists(), "launcher mutation backup already exists")
        LAUNCHER.rename(LAUNCHER_BACKUP)
        shutil.copy2(LAUNCHER_BACKUP, LAUNCHER)
        os.chown(LAUNCHER, 0, 0)
        os.chmod(LAUNCHER, 0o555)
        (STATE / "post-auth-mutation-applied").write_text(str(LAUNCHER) + "\n", encoding="ascii")


def main():
    mode = sys.argv[1]
    SOCKET.parent.mkdir(parents=True, exist_ok=True)
    try:
        SOCKET.unlink()
    except FileNotFoundError:
        pass
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as listener:
        listener.bind(str(SOCKET))
        os.chown(SOCKET, 0, 0)
        os.chmod(SOCKET, 0o600)
        listener.listen(1)
        with listener.accept()[0] as connection:
            raw = connection.recv(16 * 1024 + 1)
            request, manifest = validate_request(raw)
            (STATE / "authority-request-observed").write_text(request_digest(request) + "\n", encoding="ascii")
            if mode == "timeout":
                time.sleep(5)
                return
            if mode == "replay":
                response = REPLAY.read_bytes()
            elif mode == "malformed":
                response = b"{"
            elif mode == "oversized":
                response = b"x" * (16 * 1024 + 1)
            else:
                response = build_envelope(request, mode)
                if mode == "noncanonical":
                    response += b"\n"
            mutate_after_request(mode, manifest)
            sent = connection.send(response)
            require(sent == len(response), "authorization response was not sent atomically")
            if mode == "valid":
                REPLAY.write_bytes(response)
            time.sleep(0.1)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("test launch authority error: " + str(error), file=sys.stderr)
        sys.exit(1)
'''

FIXTURE_DRIVER = r'''
from __future__ import annotations

import hashlib
import json
import os
import signal
import stat
import subprocess
import time
from pathlib import Path


LAUNCHER = Path("/opt/serverware/bin/serverware-production-launcher-test")
LAUNCHER_BACKUP = LAUNCHER.with_name(LAUNCHER.name + ".authority-original")
AUTHORITY = "/usr/local/libexec/launch_authority_fixture.py"
AUTHORITY_SOCKET = Path("/run/serverware/launch-authority.sock")
MANIFEST = Path("/etc/serverware/production-release-launch.json")
STATE = Path("/var/lib/serverware/production-proof")
RELEASE_ROOT = Path("/opt/serverware/release")
MARKERS = (
    "preflight-python-started",
    "readiness-python-started",
    "preflight-ran",
    "readiness-ran",
    "preflight-receipt-ok",
    "readiness-receipt-ok",
    "hostile-loader-ran",
    "hostile-site-ran",
    "readiness-source-mutated",
    "mutated-readiness-ran",
    "authority-request-observed",
    "post-auth-mutation-applied",
    "delay-preflight-until-authorization-expires",
)


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def reset_markers():
    for name in MARKERS:
        try:
            (STATE / name).unlink()
        except FileNotFoundError:
            pass


def wait_for_authority(authority):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if authority.poll() is not None:
            _, stderr = authority.communicate()
            raise AssertionError("launch authority exited before binding: " + stderr)
        try:
            metadata = AUTHORITY_SOCKET.lstat()
        except FileNotFoundError:
            time.sleep(0.01)
            continue
        require(stat.S_ISSOCK(metadata.st_mode), "launch authority fixture is not a socket")
        require((metadata.st_uid, metadata.st_gid) == (0, 0), "launch authority socket is not root-owned")
        require(metadata.st_mode & 0o002 == 0, "launch authority socket is world-writable")
        return
    raise AssertionError("launch authority did not bind its socket")


def launch(*extra, authority_mode="valid", hostile=False, fd9=False, nonroot=False, timeout=60):
    try:
        AUTHORITY_SOCKET.unlink()
    except FileNotFoundError:
        pass
    authority = None
    if authority_mode is not None:
        authority = subprocess.Popen(
            ["/usr/local/bin/python3", "-I", "-S", AUTHORITY, authority_mode],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        wait_for_authority(authority)

    command = [str(LAUNCHER), "--manifest", str(MANIFEST), *extra]
    environment = os.environ.copy()
    if hostile:
        environment.update(
            {
                "LD_PRELOAD": "/opt/serverware/hostile/hostile.so",
                "LD_AUDIT": "/opt/serverware/hostile/hostile.so",
                "PYTHONPATH": "/opt/serverware/hostile/python",
                "PYTHONHOME": "/opt/serverware/hostile/python-home",
            }
        )

    inherited = ()
    if fd9:
        source_fd = os.open("/etc/hostname", os.O_RDONLY)
        os.dup2(source_fd, 9)
        if source_fd != 9:
            os.close(source_fd)
        os.set_inheritable(9, True)
        inherited = (9,)

    def demote():
        os.setgroups([])
        os.setgid(65534)
        os.setuid(65534)

    started = time.monotonic()
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            env=environment,
            pass_fds=inherited,
            preexec_fn=demote if nonroot else None,
            text=True,
            timeout=timeout,
        )
    finally:
        if fd9:
            os.close(9)
    elapsed = time.monotonic() - started

    if authority is not None:
        try:
            _, authority_stderr = authority.communicate(timeout=0.5)
        except subprocess.TimeoutExpired:
            authority.terminate()
            try:
                _, authority_stderr = authority.communicate(timeout=2)
            except subprocess.TimeoutExpired:
                authority.kill()
                _, authority_stderr = authority.communicate()
        if authority.returncode not in (0, -signal.SIGTERM):
            raise AssertionError(
                "launch authority fixture failed with "
                + str(authority.returncode)
                + ": "
                + authority_stderr
            )
    try:
        AUTHORITY_SOCKET.unlink()
    except FileNotFoundError:
        pass
    return result, elapsed


def assert_no_python(name):
    for marker in (
        "preflight-python-started",
        "readiness-python-started",
        "preflight-ran",
        "readiness-ran",
    ):
        require(not (STATE / marker).exists(), name + " reached Python: " + marker)


def rejected(name, expected, *extra, authority_mode="valid", nonroot=False, observed=None):
    reset_markers()
    result, elapsed = launch(*extra, authority_mode=authority_mode, nonroot=nonroot)
    require(result.returncode != 0, name + " unexpectedly succeeded")
    require(expected in result.stderr, name + " did not report the expected rejection: " + result.stderr)
    assert_no_python(name)
    if observed is not None:
        require(
            (STATE / "authority-request-observed").exists() == observed,
            name + " had the wrong authority request state",
        )
    return result, elapsed


def restore_bytes(path, original, mode):
    with path.open("r+b", buffering=0) as target:
        target.write(original)
        target.truncate()
    os.chmod(path, mode)


def write_manifest(manifest, mode):
    encoded = json.dumps(
        manifest, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii")
    restore_bytes(MANIFEST, encoded, mode)


def import_root_contract_rejected(name, mode, expected):
    original = MANIFEST.read_bytes()
    original_mode = stat.S_IMODE(MANIFEST.stat().st_mode)
    manifest = json.loads(original.decode("utf-8"))
    roots = manifest["python"]["importRoots"]
    if mode == "missing-lib-dynload":
        roots.pop(2)
    elif mode == "reordered-lib-dynload":
        roots[2], roots[3] = roots[3], roots[2]
    elif mode == "wrong-lib-dynload":
        roots[2]["path"] = str(RELEASE_ROOT / "runtime/python/lib/lib-dynload")
    elif mode == "wrong-interpreter-version":
        roots[1]["path"] = str(RELEASE_ROOT / "runtime/python/lib/python3.12")
        roots[2]["path"] = str(RELEASE_ROOT / "runtime/python/lib/python3.12/lib-dynload")
    else:
        raise AssertionError("unknown import-root mutation: " + mode)
    try:
        write_manifest(manifest, original_mode)
        rejected(name, expected, observed=False)
    finally:
        restore_bytes(MANIFEST, original, original_mode)


def wrong_libpython_version_rejected():
    python_path = RELEASE_ROOT / "runtime/python/bin/python3"
    original_python = python_path.read_bytes()
    python_mode = stat.S_IMODE(python_path.stat().st_mode)
    original_manifest = MANIFEST.read_bytes()
    manifest_mode = stat.S_IMODE(MANIFEST.stat().st_mode)
    expected = b"libpython3.11.so.1.0"
    replacement = b"libpython3.12.so.1.0"
    require(
        original_python.count(expected) > 0,
        "fixture Python ELF omits its libpython3.11 dependency metadata",
    )
    mutated_python = original_python.replace(expected, replacement)
    manifest = json.loads(original_manifest.decode("utf-8"))
    manifest["python"]["sha256"] = "sha256:" + hashlib.sha256(mutated_python).hexdigest()
    try:
        restore_bytes(python_path, mutated_python, python_mode)
        write_manifest(manifest, manifest_mode)
        rejected(
            "wrong libpython version",
            "python ELF does not depend on a compatible libpython3.11.so",
            observed=False,
        )
    finally:
        restore_bytes(MANIFEST, original_manifest, manifest_mode)
        restore_bytes(python_path, original_python, python_mode)


def post_authorization_file_rejected(name, mode, path, expected):
    original = path.read_bytes()
    original_mode = stat.S_IMODE(path.stat().st_mode)
    try:
        rejected(name, expected, authority_mode=mode, observed=True)
        require((STATE / "post-auth-mutation-applied").is_file(), name + " did not mutate its target")
    finally:
        restore_bytes(path, original, original_mode)


def main():
    scenarios = 0
    reset_markers()
    fd9_expectation = STATE / "expect-inherited-fd9-closed"
    fd9_expectation.write_text("1\n", encoding="ascii")
    try:
        valid, _ = launch(hostile=True, fd9=True)
    finally:
        fd9_expectation.unlink()
    require(valid.returncode == 0, "valid launch failed: " + valid.stderr)
    for marker in (
        "preflight-python-started",
        "readiness-python-started",
        "preflight-ran",
        "readiness-ran",
        "preflight-receipt-ok",
        "readiness-receipt-ok",
        "authority-request-observed",
    ):
        require((STATE / marker).is_file(), "valid launch omitted " + marker)
    require(not (STATE / "hostile-loader-ran").exists(), "hostile dynamic-loader environment executed")
    require(not (STATE / "hostile-site-ran").exists(), "hostile sitecustomize executed")
    scenarios += 1

    rejected("replayed authorization", "LAUTH_REQUEST_MISMATCH", authority_mode="replay", observed=True)
    scenarios += 1

    preflight_path = RELEASE_ROOT / "scripts/preflight.py"
    post_authorization_file_rejected(
        "post-authorization preflight mutation",
        "post-auth-preflight-mutation",
        preflight_path,
        "python.importRoots[0] post-authorization digest does not match",
    )
    scenarios += 1

    reset_markers()
    readiness_switch = STATE / "mutate-readiness-source"
    readiness_path = RELEASE_ROOT / "scripts/runner.py"
    original_readiness = readiness_path.read_bytes()
    readiness_mode = stat.S_IMODE(readiness_path.stat().st_mode)
    readiness_switch.write_text("1\n", encoding="ascii")
    try:
        mutated_readiness, _ = launch()
    finally:
        readiness_switch.unlink()
        restore_bytes(readiness_path, original_readiness, readiness_mode)
    require(mutated_readiness.returncode != 0, "post-preflight readiness mutation unexpectedly succeeded")
    require(
        "python.importRoots[0] post-authorization digest does not match" in mutated_readiness.stderr,
        "readiness mutation did not trigger post-authorization remeasurement: " + mutated_readiness.stderr,
    )
    require((STATE / "preflight-ran").is_file(), "preflight did not run before readiness mutation rejection")
    require((STATE / "readiness-source-mutated").is_file(), "preflight did not mutate readiness source")
    require(not (STATE / "readiness-ran").exists(), "readiness ran after its source changed")
    require(not (STATE / "mutated-readiness-ran").exists(), "mutated readiness source bytes executed")
    scenarios += 1

    reset_markers()
    expiry_switch = STATE / "delay-preflight-until-authorization-expires"
    expiry_switch.write_text("1\n", encoding="ascii")
    try:
        expired_between_phases, _ = launch(authority_mode="expires-during-preflight")
    finally:
        expiry_switch.unlink(missing_ok=True)
    require(
        expired_between_phases.returncode != 0,
        "authorization that expired during preflight unexpectedly reached the runner",
    )
    require(
        "LAUTH_EXPIRED" in expired_between_phases.stderr,
        "post-preflight expiry did not report LAUTH_EXPIRED: " + expired_between_phases.stderr,
    )
    require((STATE / "preflight-ran").is_file(), "short-lived authorization did not reach preflight")
    require(not (STATE / "readiness-ran").exists(), "runner used an authorization expired by preflight")
    scenarios += 1

    pre_authorization_cases = (
        ("non-root invocation", "effective UID 0", (), {"nonroot": True}),
        ("unknown argument", "unknown launcher argument", ("--arbitrary", "value"), {}),
        ("duplicate argument", "duplicate --manifest argument", ("--manifest", str(MANIFEST)), {}),
        (
            "manifest digest override",
            "unknown launcher argument: --manifest-sha256",
            ("--manifest-sha256", "sha256:" + "0" * 64),
            {},
        ),
    )
    for name, expected, extra, options in pre_authorization_cases:
        rejected(name, expected, *extra, observed=False, **options)
        scenarios += 1

    os.chmod(MANIFEST, 0o644)
    try:
        rejected("wrong manifest mode", "manifest mode must be exactly 0400 or 0440", observed=False)
    finally:
        os.chmod(MANIFEST, 0o400)
    scenarios += 1

    os.chown(MANIFEST, 65534, 65534)
    try:
        rejected("wrong manifest owner", "manifest must be owned by root:root", observed=False)
    finally:
        os.chown(MANIFEST, 0, 0)
    scenarios += 1

    real_manifest = MANIFEST.with_suffix(".real")
    MANIFEST.rename(real_manifest)
    MANIFEST.symlink_to(real_manifest)
    try:
        rejected("symlink manifest", "could not securely open manifest", observed=False)
    finally:
        MANIFEST.unlink()
        real_manifest.rename(MANIFEST)
    scenarios += 1

    import_root_contract_rejected(
        "missing lib-dynload import root",
        "missing-lib-dynload",
        "python.importRoots must contain exactly four ordered roots",
    )
    scenarios += 1

    import_root_contract_rejected(
        "reordered lib-dynload import root",
        "reordered-lib-dynload",
        "python.importRoots must be ordered as releaseRoot, stdlib, lib-dynload, vendor",
    )
    scenarios += 1

    import_root_contract_rejected(
        "wrong lib-dynload import root",
        "wrong-lib-dynload",
        "python.importRoots must be ordered as releaseRoot, stdlib, lib-dynload, vendor",
    )
    scenarios += 1

    import_root_contract_rejected(
        "wrong interpreter version",
        "wrong-interpreter-version",
        "python ELF does not depend on a compatible libpython3.12.so",
    )
    scenarios += 1

    wrong_libpython_version_rejected()
    scenarios += 1

    mutation = RELEASE_ROOT / "unexpected_mutation.py"
    mutation.write_text("raise RuntimeError('must never import')\n", encoding="ascii")
    os.chmod(mutation, 0o444)
    try:
        rejected("import-root mutation", "python.importRoots[0] digest does not match", observed=False)
    finally:
        mutation.unlink()
    scenarios += 1

    reset_markers()
    failure_switch = STATE / "force-preflight-fail"
    failure_switch.write_text("1\n", encoding="ascii")
    try:
        failed_preflight, _ = launch()
    finally:
        failure_switch.unlink()
    require(
        failed_preflight.returncode == 23,
        "preflight status was not preserved: " + str(failed_preflight.returncode) + " " + failed_preflight.stderr,
    )
    require((STATE / "preflight-ran").is_file(), "failing preflight did not execute")
    require(not (STATE / "readiness-ran").exists(), "readiness ran after preflight rejection")
    scenarios += 1

    rejected(
        "missing launch authority relay",
        "LAUTH_SOCKET_UNAVAILABLE",
        authority_mode=None,
        observed=False,
    )
    scenarios += 1

    _, timeout_elapsed = rejected(
        "launch authority timeout",
        "LAUTH_TIMEOUT",
        authority_mode="timeout",
        observed=True,
    )
    require(1.5 <= timeout_elapsed < 5.0, "launch authority timeout was not bounded: " + str(timeout_elapsed))
    scenarios += 1

    authorization_cases = (
        ("wrong signing key", "LAUTH_SIGNATURE_INVALID", "wrong-signing-key"),
        ("wrong request digest", "LAUTH_REQUEST_MISMATCH", "wrong-request-digest"),
        ("expired authorization", "LAUTH_EXPIRED", "expired"),
        ("future authorization", "LAUTH_FUTURE", "future"),
        ("overlong authorization", "LAUTH_TIME_INVALID", "overlong"),
        ("malformed authorization", "LAUTH_SCHEMA_INVALID", "malformed"),
        ("noncanonical authorization", "LAUTH_FRAME_INVALID", "noncanonical"),
        ("oversized authorization", "LAUTH_FRAME_INVALID", "oversized"),
    )
    for name, expected, mode in authorization_cases:
        rejected(name, expected, authority_mode=mode, observed=True)
        scenarios += 1

    binding_cases = (
        ("manifest authorization binding", "bind-manifest"),
        ("release provenance authorization binding", "bind-release-provenance"),
        ("provenance identity authorization binding", "bind-provenance-digest"),
        ("source tree authorization binding", "bind-source-tree"),
        ("launcher authorization binding", "bind-launcher"),
        ("reproducible build authorization binding", "bind-reproducible-build"),
        ("release sequence authorization binding", "bind-release-sequence"),
        ("rollback epoch authorization binding", "bind-rollback-epoch"),
    )
    for name, mode in binding_cases:
        rejected(name, "LAUTH_REQUEST_MISMATCH", authority_mode=mode, observed=True)
        scenarios += 1

    manifest_original = MANIFEST.read_bytes()
    manifest_mode = stat.S_IMODE(MANIFEST.stat().st_mode)
    try:
        post_authorization_file_rejected(
            "post-authorization manifest mutation",
            "post-auth-manifest-mutation",
            MANIFEST,
            "manifest changed after launch authorization",
        )
    finally:
        restore_bytes(MANIFEST, manifest_original, manifest_mode)
    scenarios += 1

    provenance_path = RELEASE_ROOT / "evidence/releaseProvenance.json"
    post_authorization_file_rejected(
        "post-authorization provenance mutation",
        "post-auth-provenance-mutation",
        provenance_path,
        "python.importRoots[0] post-authorization digest does not match",
    )
    scenarios += 1

    reproducible_path = RELEASE_ROOT / "evidence/reproducibleBuildVerification.json"
    post_authorization_file_rejected(
        "post-authorization reproducible build mutation",
        "post-auth-repro-mutation",
        reproducible_path,
        "python.importRoots[0] post-authorization digest does not match",
    )
    scenarios += 1

    try:
        rejected(
            "post-authorization launcher mutation",
            "launcher executable changed after launch authorization",
            authority_mode="post-auth-launcher-mutation",
            observed=True,
        )
        require((STATE / "post-auth-mutation-applied").is_file(), "launcher mutation was not applied")
    finally:
        if LAUNCHER_BACKUP.exists():
            LAUNCHER.unlink(missing_ok=True)
            LAUNCHER_BACKUP.rename(LAUNCHER)
    scenarios += 1

    require(scenarios == 41, "scenario count drifted: " + str(scenarios))
    print("production launcher adversarial fixture: PASS (41 scenarios)")


if __name__ == "__main__":
    main()
'''


def dockerfile() -> str:
    separator = f" {chr(92)}\n        "
    input_args = separator.join(
        f"--{argument} /opt/serverware/release/evidence/{name}.json"
        for argument, name in INPUTS
    )
    output_args = separator.join(
        f"--{argument} /var/lib/serverware/production-proof/{filename}"
        for argument, filename in OUTPUTS
    )
    names = " ".join(name for _, name in INPUTS)
    provenance = (
        '{"provenance":{"source":"serverware-digest-pinned-production-release","source_tree":{"digest":"'
        + SOURCE_TREE_DIGEST
        + '"},"version":2},"provenance_digest":"'
        + PROVENANCE_DIGEST
        + '"}'
    )
    return textwrap.dedent(
        f"""\
        FROM rust:1.88-slim-bookworm AS hostile-build
        COPY hostile.c /src/hostile.c
        RUN cc -shared -fPIC -Wl,-z,relro,-z,now -o /hostile.so /src/hostile.c

        FROM rust:1.88-alpine3.22 AS launcher-build
        ARG SOURCE_DATE_EPOCH="0"
        ENV SOURCE_DATE_EPOCH=${{SOURCE_DATE_EPOCH}} \\
            RUSTFLAGS="-C link-arg=-Wl,--build-id=none"
        WORKDIR /src
        RUN apk add --no-cache musl=1.2.5-r12 musl-dev=1.2.5-r12
        COPY decision-gate-rs/Cargo.toml ./Cargo.toml
        COPY decision-gate-rs/Cargo.lock ./Cargo.lock
        COPY decision-gate-rs/src ./src
        COPY decision-gate-rs/trust ./trust
        RUN cargo build --release --locked --bin serverware-production-launcher \\
            && test "$(readelf -l /src/target/release/serverware-production-launcher | grep -c INTERP)" -eq 0 \\
            && test "$(readelf -d /src/target/release/serverware-production-launcher | grep -c NEEDED)" -eq 0

        FROM python:3.11-slim-bookworm
        COPY --from=launcher-build --chown=0:0 --chmod=0555 /src/target/release/serverware-production-launcher /opt/serverware/bin/serverware-production-launcher-test
        COPY --chown=0:0 --chmod=0555 generate_production_launch_manifest.py /usr/local/libexec/generate_production_launch_manifest.py
        COPY --chown=0:0 --chmod=0500 launch_authority_fixture.py /usr/local/libexec/launch_authority_fixture.py
        COPY --chown=0:0 --chmod=0400 test-launch-authority-private.pem /etc/serverware/test-launch-authority-private.pem
        COPY --chown=0:0 --chmod=0400 test-launch-authority-wrong-private.pem /etc/serverware/test-launch-authority-wrong-private.pem
        COPY --chown=0:0 --chmod=0400 preflight.py /opt/serverware/release/scripts/preflight.py
        COPY --chown=0:0 --chmod=0400 runner.py /opt/serverware/release/scripts/runner.py
        COPY --chown=0:0 --chmod=0500 fixture_driver.py /usr/local/libexec/fixture_driver.py
        COPY --from=hostile-build --chown=0:0 --chmod=0555 /hostile.so /opt/serverware/hostile/hostile.so
        RUN set -eu; \\
            openssl version; \\
            mkdir -p /run/serverware \\
                /opt/serverware/release/runtime/python/bin \\
                /opt/serverware/release/runtime/python/lib/python3.11 \\
                /opt/serverware/release/vendor \\
                /opt/serverware/release/evidence \\
                /opt/serverware/hostile/python \\
                /opt/serverware/hostile/python-home \\
                /var/lib/serverware/production-proof; \\
            cp /usr/local/bin/python3.11 /opt/serverware/release/runtime/python/bin/python3; \\
            cp /usr/local/lib/libpython3.11.so.1.0 /opt/serverware/release/runtime/python/lib/libpython3.11.so.1.0; \\
            cp -RL /usr/local/lib/python3.11/. /opt/serverware/release/runtime/python/lib/python3.11/; \\
            rm -rf /opt/serverware/release/runtime/python/lib/python3.11/site-packages \\
                /opt/serverware/release/runtime/python/lib/python3.11/ensurepip \\
                /opt/serverware/release/runtime/python/lib/python3.11/idlelib \\
                /opt/serverware/release/runtime/python/lib/python3.11/tkinter \\
                /opt/serverware/release/runtime/python/lib/python3.11/__pycache__; \\
            find /opt/serverware/release/runtime/python/lib/python3.11 -type d -exec chmod 0755 {{}} +; \\
            find /opt/serverware/release/runtime/python/lib/python3.11 -type f -exec chmod 0444 {{}} +; \\
            test -f /opt/serverware/release/runtime/python/lib/libpython3.11.so.1.0; \\
            test -n "$(find /opt/serverware/release/runtime/python/lib/python3.11/lib-dynload -maxdepth 1 -type f -name '*.so' -print -quit)"; \\
            printf '__all__ = []\\n' > /opt/serverware/release/vendor/serverware_vendor.py; \\
            chmod 0444 /opt/serverware/release/vendor/serverware_vendor.py; \\
            chown -R 0:0 /opt/serverware /var/lib/serverware/production-proof /run/serverware; \\
            chmod 0500 /opt/serverware/release/runtime/python/bin/python3; \\
            chmod 0444 /opt/serverware/release/runtime/python/lib/libpython3.11.so.1.0; \\
            chmod 0700 /var/lib/serverware/production-proof; \\
            chmod 0755 /run/serverware; \\
            printf 'services: {{}}\\n' > /opt/serverware/release/docker-compose.production.yml; \\
            chmod 0444 /opt/serverware/release/docker-compose.production.yml; \\
            printf 'SERVERWARE_TEST=1\\n' > /etc/serverware/production-readiness.env; \\
            chmod 0400 /etc/serverware/production-readiness.env; \\
            for name in {names}; do \\
                printf '{{"fixture":true}}\\n' > "/opt/serverware/release/evidence/$name.json"; \\
                chmod 0444 "/opt/serverware/release/evidence/$name.json"; \\
            done; \\
            printf '%s\\n' '{provenance}' > /opt/serverware/release/evidence/releaseProvenance.json; \\
            printf '%s\\n' 'open("/var/lib/serverware/production-proof/hostile-site-ran", "w").write("hostile site executed\\n")' \\
                > /opt/serverware/hostile/python/sitecustomize.py; \\
            cp /opt/serverware/hostile/python/sitecustomize.py /usr/local/lib/python3.11/sitecustomize.py; \\
            chmod 0444 /opt/serverware/hostile/python/sitecustomize.py /usr/local/lib/python3.11/sitecustomize.py; \\
            python3 /usr/local/libexec/generate_production_launch_manifest.py \\
                --output /etc/serverware/production-release-launch.json \\
                --release-root /opt/serverware/release \\
                --state-directory /var/lib/serverware/production-proof \\
                --source-tree-digest {SOURCE_TREE_DIGEST} \\
                --deployment-audience {DEPLOYMENT_AUDIENCE} \\
                --deployment-identity-sha256 {DEPLOYMENT_IDENTITY_DIGEST} \\
                --release-sequence {RELEASE_SEQUENCE} \\
                --rollback-epoch {ROLLBACK_EPOCH} \\
                --production-env /etc/serverware/production-readiness.env \\
                --python /opt/serverware/release/runtime/python/bin/python3 \\
                --python-import-root /opt/serverware/release \\
                --python-import-root /opt/serverware/release/runtime/python/lib/python3.11 \\
                --python-import-root /opt/serverware/release/runtime/python/lib/python3.11/lib-dynload \\
                --python-import-root /opt/serverware/release/vendor \\
                --preflight-script /opt/serverware/release/scripts/preflight.py \\
                --runner-script /opt/serverware/release/scripts/runner.py \\
                --compose-file /opt/serverware/release/docker-compose.production.yml \\
                {input_args} \\
                {output_args}; \\
            test "$(stat -c '%u:%g:%a' /etc/serverware/production-release-launch.json)" = '0:0:400'
        ENTRYPOINT ["/usr/local/bin/python3", "/usr/local/libexec/fixture_driver.py"]
        """
    )


def run(command: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as error:
        raise RuntimeError(f"required command is unavailable: {command[0]}") from error
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f"command timed out after {timeout}s: {' '.join(command[:4])}") from error


def require_success(result: subprocess.CompletedProcess[str], label: str) -> None:
    if result.returncode == 0:
        return
    output = (result.stdout + result.stderr).strip()
    if len(output) > 6000:
        output = output[-6000:]
    raise RuntimeError(f"{label} failed with exit {result.returncode}:\n{output}")


def generate_ephemeral_authority(context: Path, production_public: bytes) -> tuple[str, str]:
    private_key = context / "test-launch-authority-private.pem"
    wrong_private_key = context / "test-launch-authority-wrong-private.pem"
    public_der = context / "test-launch-authority-public.der"
    for path in (private_key, wrong_private_key):
        require_success(
            run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(path)], 30),
            "ephemeral Ed25519 key generation",
        )
        os.chmod(path, 0o600)
    require_success(
        run(
            [
                "openssl",
                "pkey",
                "-in",
                str(private_key),
                "-pubout",
                "-outform",
                "DER",
                "-out",
                str(public_der),
            ],
            30,
        ),
        "ephemeral Ed25519 public key extraction",
    )
    spki = public_der.read_bytes()
    public_der.unlink()
    if len(spki) != len(ED25519_SPKI_PREFIX) + 32 or not spki.startswith(ED25519_SPKI_PREFIX):
        raise RuntimeError("OpenSSL returned an unexpected Ed25519 SubjectPublicKeyInfo")
    public = spki[len(ED25519_SPKI_PREFIX) :]
    production_hex = production_public.decode("ascii").strip()
    if public.hex() == production_hex:
        raise RuntimeError("ephemeral test authority unexpectedly matches the production trust root")
    return public.hex(), "sha256:" + hashlib.sha256(spki).hexdigest()


def write_context(context: Path, public_key_hex: str, authority_key_id: str) -> None:
    crate = context / "decision-gate-rs"
    (crate / "trust").mkdir(parents=True)
    shutil.copyfile(CRATE / "Cargo.toml", crate / "Cargo.toml")
    shutil.copyfile(CRATE / "Cargo.lock", crate / "Cargo.lock")
    shutil.copytree(CRATE / "src", crate / "src")
    (crate / "trust/launch-authority-root.ed25519.hex").write_text(
        public_key_hex + "\n", encoding="ascii"
    )
    shutil.copyfile(GENERATOR, context / "generate_production_launch_manifest.py")
    files = {
        "Dockerfile": dockerfile(),
        "hostile.c": HOSTILE_C,
        "preflight.py": PREFLIGHT.replace("__AUTHORITY_KEY_ID__", authority_key_id),
        "runner.py": RUNNER.replace("__AUTHORITY_KEY_ID__", authority_key_id),
        "launch_authority_fixture.py": AUTHORITY_FIXTURE.replace("__PUBLIC_KEY_HEX__", public_key_hex),
        "fixture_driver.py": FIXTURE_DRIVER,
    }
    for name, content in files.items():
        (context / name).write_text(content, encoding="ascii")


def main() -> int:
    if not PRODUCTION_TRUST.is_file():
        raise RuntimeError(f"production launch authority trust root is missing: {PRODUCTION_TRUST}")
    if not GENERATOR.is_file():
        raise RuntimeError(f"manifest generator is missing: {GENERATOR}")
    production_trust_before = PRODUCTION_TRUST.read_bytes()
    require_success(
        run(["docker", "version", "--format", "{{.Server.Os}}/{{.Server.Arch}}"], 30),
        "Docker availability check",
    )
    require_success(run(["openssl", "version"], 30), "OpenSSL availability check")

    image = ""
    try:
        with tempfile.TemporaryDirectory(prefix="serverware-launcher-adversarial-") as temporary:
            context = Path(temporary)
            public_key_hex, authority_key_id = generate_ephemeral_authority(
                context, production_trust_before
            )
            write_context(context, public_key_hex, authority_key_id)
            image = (
                "serverware-production-launcher-adversarial:"
                + public_key_hex[:12]
                + "-"
                + uuid.uuid4().hex[:8]
            )
            require_success(
                run(
                    [
                        "docker",
                        "build",
                        "--platform",
                        PLATFORM,
                        "--quiet",
                        "--tag",
                        image,
                        str(context),
                    ],
                    900,
                ),
                "adversarial fixture image build",
            )

        if PRODUCTION_TRUST.read_bytes() != production_trust_before:
            raise RuntimeError("production launch authority trust root changed during test build")
        architecture = run(
            ["docker", "image", "inspect", "--format", "{{.Architecture}}", image],
            30,
        )
        require_success(architecture, "fixture architecture inspection")
        if architecture.stdout.strip() != "amd64":
            raise RuntimeError(f"fixture image architecture is not amd64: {architecture.stdout.strip()!r}")

        fixture = run(
            ["docker", "run", "--rm", "--platform", PLATFORM, image],
            600,
        )
        require_success(fixture, "adversarial fixture scenarios")
        print(fixture.stdout.strip())
        return 0
    finally:
        if image:
            run(["docker", "image", "rm", "--force", image], 60)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError) as error:
        print(f"production launcher adversarial test error: {error}", file=sys.stderr)
        sys.exit(1)
