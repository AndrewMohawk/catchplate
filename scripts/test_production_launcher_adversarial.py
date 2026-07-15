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
LAUNCHER = ROOT / ".tmp/production-launcher-artifact/serverware-production-launcher"
GENERATOR = ROOT / "scripts/generate_production_launch_manifest.py"
PLATFORM = "linux/amd64"

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
import fcntl
import hashlib
import json
import os

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


def canonical(value):
    return json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def digest(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def validate_child(phase):
    assert os.getcwd() == "/opt/serverware/release"
    assert os.environ["LANG"] == "C.UTF-8"
    assert os.environ["LC_ALL"] == "C.UTF-8"
    assert os.environ["PATH"] == "/usr/sbin:/usr/bin:/sbin:/bin"
    assert os.environ["TZ"] == "UTC"
    assert os.environ["SERVERWARE_BOOTSTRAP_RECEIPT_API_VERSION"] == "serverware.bootstrapReceipt/v1"
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
    assert receipt["apiVersion"] == "serverware.bootstrapReceipt/v1"
    assert receipt["kind"] == "ProductionBootstrapReceipt"
    assert receipt["sourceTreeDigest"] == "sha256:" + "a" * 64
    assert len(receipt["launchId"]) == 64
    int(receipt["launchId"], 16)
    assert receipt["bootIdSha256"].startswith("sha256:")
    with open("/etc/serverware/production-release-launch.json", "rb") as source:
        assert receipt["manifest"]["sha256"] == digest(source.read())
    assert [root["path"] for root in receipt["python"]["importRoots"]] == [
        "/opt/serverware/release/python/lib/python3.12",
        "/opt/serverware/release/python/lib/python3.12/lib-dynload",
    ]
    for name in ("preflightSha256", "readinessSha256"):
        assert len(receipt["argv"][name]) == 71
        assert receipt["argv"][name].startswith("sha256:")

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
        "SERVERWARE_BOOTSTRAP_RECEIPT_API_VERSION": "serverware.bootstrapReceipt/v1",
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

FIXTURE_DRIVER = r'''
from __future__ import annotations

import os
import fcntl
import signal
import subprocess
import time
from pathlib import Path


LAUNCHER = "/opt/serverware/bin/serverware-production-launcher"
MANIFEST = Path("/etc/serverware/production-release-launch.json")
DIGEST = Path(
    "/etc/serverware/production-release-launch.sha256"
).read_text(encoding="ascii").strip()
STATE = Path("/var/lib/serverware/production-proof")
IMPORT_ROOT = Path("/opt/serverware/release/python/lib/python3.12")
MARKERS = (
    "preflight-ran",
    "readiness-ran",
    "preflight-receipt-ok",
    "readiness-receipt-ok",
    "hostile-loader-ran",
    "hostile-site-ran",
    "preflight-source-mutated",
    "readiness-source-mutated",
    "mutated-preflight-ran",
    "mutated-readiness-ran",
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


def launch(*extra, digest=DIGEST, hostile=False, fd9=False, nonroot=False):
    command = [
        LAUNCHER,
        "--manifest",
        str(MANIFEST),
        "--manifest-sha256",
        digest,
        *extra,
    ]
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

    try:
        return subprocess.run(
            command,
            check=False,
            capture_output=True,
            env=environment,
            pass_fds=inherited,
            preexec_fn=demote if nonroot else None,
            text=True,
            timeout=60,
        )
    finally:
        if fd9:
            os.close(9)


def rejected(name, expected, *extra, digest=DIGEST, nonroot=False):
    reset_markers()
    result = launch(*extra, digest=digest, nonroot=nonroot)
    require(result.returncode != 0, name + " unexpectedly succeeded")
    require(
        expected in result.stderr,
        name + " did not report the expected rejection: " + result.stderr,
    )
    require(not (STATE / "preflight-ran").exists(), name + " reached preflight")
    require(not (STATE / "readiness-ran").exists(), name + " reached readiness")


def launch_with_post_measurement_preflight_mutation():
    command = [
        LAUNCHER,
        "--manifest",
        str(MANIFEST),
        "--manifest-sha256",
        DIGEST,
    ]
    preflight_path = Path("/opt/serverware/release/scripts/preflight.py")
    original = preflight_path.read_bytes()
    original_identity = preflight_path.stat()
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    stopped = False
    mutated = False
    try:
        deadline = time.monotonic() + 30
        required_seals = (
            fcntl.F_SEAL_WRITE
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_SEAL
        )
        while time.monotonic() < deadline and process.poll() is None:
            descriptor_root = Path(f"/proc/{process.pid}/fd")
            try:
                descriptors = list(descriptor_root.iterdir())
            except FileNotFoundError:
                break
            sealed_snapshot = False
            for descriptor in descriptors:
                try:
                    target = os.readlink(descriptor)
                    if "serverware-preflight-script-snapshot" not in target:
                        continue
                    probe_fd = os.open(descriptor, os.O_RDONLY | os.O_CLOEXEC)
                    try:
                        seals = fcntl.fcntl(probe_fd, fcntl.F_GET_SEALS)
                    finally:
                        os.close(probe_fd)
                    sealed_snapshot = seals & required_seals == required_seals
                except (FileNotFoundError, OSError):
                    continue
                if sealed_snapshot:
                    break
            if not sealed_snapshot:
                time.sleep(0.001)
                continue

            os.kill(process.pid, signal.SIGSTOP)
            stopped = True
            stop_deadline = time.monotonic() + 5
            while time.monotonic() < stop_deadline:
                status = Path(f"/proc/{process.pid}/status").read_text(encoding="ascii")
                if "State:\tT" in status:
                    break
                time.sleep(0.001)
            else:
                raise AssertionError("launcher did not stop before script mutation")
            children = Path(f"/proc/{process.pid}/task/{process.pid}/children").read_text(
                encoding="ascii"
            )
            require(not children.strip(), "launcher forked before preflight source mutation")

            hostile = (
                b"open('/var/lib/serverware/production-proof/mutated-preflight-ran', 'w').write('bad\\n')\n"
                b"raise SystemExit(90)\n"
            )
            with preflight_path.open("r+b", buffering=0) as target:
                target.write(hostile)
                target.truncate()
            mutated_identity = preflight_path.stat()
            require(
                (original_identity.st_dev, original_identity.st_ino)
                == (mutated_identity.st_dev, mutated_identity.st_ino),
                "preflight mutation replaced the inode",
            )
            (STATE / "preflight-source-mutated").write_text(
                "same inode\n", encoding="ascii"
            )
            mutated = True
            os.kill(process.pid, signal.SIGCONT)
            stopped = False
            stdout, stderr = process.communicate(timeout=60)
            return subprocess.CompletedProcess(
                command,
                process.returncode,
                stdout,
                stderr,
            )
        raise AssertionError("did not observe a sealed preflight snapshot")
    finally:
        if stopped:
            os.kill(process.pid, signal.SIGCONT)
        if process.poll() is None:
            process.kill()
            process.communicate()
        if mutated:
            with preflight_path.open("r+b", buffering=0) as target:
                target.write(original)
                target.truncate()
            restored_identity = preflight_path.stat()
            require(
                (original_identity.st_dev, original_identity.st_ino)
                == (restored_identity.st_dev, restored_identity.st_ino),
                "preflight restoration replaced the inode",
            )


def main():
    reset_markers()
    fd9_expectation = STATE / "expect-inherited-fd9-closed"
    fd9_expectation.write_text("1\n", encoding="ascii")
    try:
        valid = launch(hostile=True, fd9=True)
    finally:
        fd9_expectation.unlink()
    require(valid.returncode == 0, "valid launch failed: " + valid.stderr)
    for marker in (
        "preflight-ran",
        "readiness-ran",
        "preflight-receipt-ok",
        "readiness-receipt-ok",
    ):
        require((STATE / marker).is_file(), "valid launch omitted " + marker)
    require(
        not (STATE / "hostile-loader-ran").exists(),
        "hostile dynamic-loader environment executed",
    )
    require(
        not (STATE / "hostile-site-ran").exists(),
        "hostile sitecustomize executed",
    )

    reset_markers()
    mutated_preflight = launch_with_post_measurement_preflight_mutation()
    require(
        mutated_preflight.returncode == 0,
        "post-measurement preflight mutation launch failed: " + mutated_preflight.stderr,
    )
    require(
        (STATE / "preflight-source-mutated").is_file(),
        "preflight source was not mutated after its snapshot was sealed",
    )
    require((STATE / "preflight-ran").is_file(), "sealed preflight snapshot did not execute")
    require((STATE / "readiness-ran").is_file(), "readiness did not follow sealed preflight")
    require(
        not (STATE / "mutated-preflight-ran").exists(),
        "mutated preflight source bytes executed",
    )

    reset_markers()
    readiness_switch = STATE / "mutate-readiness-source"
    readiness_path = Path("/opt/serverware/release/scripts/runner.py")
    original_readiness = readiness_path.read_bytes()
    readiness_identity = readiness_path.stat()
    readiness_switch.write_text("1\n", encoding="ascii")
    try:
        mutated_readiness = launch()
    finally:
        readiness_switch.unlink()
        with readiness_path.open("r+b", buffering=0) as target:
            target.write(original_readiness)
            target.truncate()
    restored_readiness_identity = readiness_path.stat()
    require(
        (readiness_identity.st_dev, readiness_identity.st_ino)
        == (restored_readiness_identity.st_dev, restored_readiness_identity.st_ino),
        "readiness restoration replaced the inode",
    )
    require(
        mutated_readiness.returncode == 0,
        "post-measurement readiness mutation launch failed: " + mutated_readiness.stderr,
    )
    require(
        (STATE / "readiness-source-mutated").is_file(),
        "preflight did not mutate the readiness source",
    )
    require((STATE / "readiness-ran").is_file(), "sealed readiness snapshot did not execute")
    require(
        not (STATE / "mutated-readiness-ran").exists(),
        "mutated readiness source bytes executed",
    )

    rejected("non-root invocation", "effective UID 0", nonroot=True)
    rejected("unknown argument", "unknown launcher argument", "--arbitrary", "value")
    rejected(
        "duplicate argument",
        "duplicate --manifest argument",
        "--manifest",
        str(MANIFEST),
    )
    rejected(
        "manifest digest mismatch",
        "manifest digest does not match",
        digest="sha256:" + "0" * 64,
    )

    os.chmod(MANIFEST, 0o644)
    try:
        rejected("wrong manifest mode", "manifest mode must be exactly 0400 or 0440")
    finally:
        os.chmod(MANIFEST, 0o400)

    os.chown(MANIFEST, 65534, 65534)
    try:
        rejected("wrong manifest owner", "manifest must be owned by root:root")
    finally:
        os.chown(MANIFEST, 0, 0)

    real_manifest = MANIFEST.with_suffix(".real")
    MANIFEST.rename(real_manifest)
    MANIFEST.symlink_to(real_manifest)
    try:
        rejected("symlink manifest", "could not securely open manifest")
    finally:
        MANIFEST.unlink()
        real_manifest.rename(MANIFEST)

    mutation = IMPORT_ROOT / "unexpected_mutation.py"
    mutation.write_text("raise RuntimeError('must never import')\n", encoding="ascii")
    os.chmod(mutation, 0o444)
    try:
        rejected(
            "import-root mutation",
            "python.importRoots[0] digest does not match",
        )
    finally:
        mutation.unlink()

    reset_markers()
    failure_switch = STATE / "force-preflight-fail"
    failure_switch.write_text("1\n", encoding="ascii")
    try:
        failed_preflight = launch()
    finally:
        failure_switch.unlink()
    require(
        failed_preflight.returncode == 23,
        "preflight status was not preserved: "
        + str(failed_preflight.returncode)
        + " "
        + failed_preflight.stderr,
    )
    require((STATE / "preflight-ran").is_file(), "failing preflight did not execute")
    require(
        not (STATE / "readiness-ran").exists(),
        "readiness ran after preflight rejection",
    )
    print("production launcher adversarial fixture: PASS (12 scenarios)")


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
    return textwrap.dedent(
        f"""\
        FROM rust:1.88-slim-bookworm AS hostile-build
        COPY hostile.c /src/hostile.c
        RUN cc -shared -fPIC -Wl,-z,relro,-z,now -o /hostile.so /src/hostile.c

        FROM python:3.12-slim-bookworm
        COPY --chown=0:0 --chmod=0555 serverware-production-launcher /opt/serverware/bin/serverware-production-launcher
        COPY --chown=0:0 --chmod=0555 generate_production_launch_manifest.py /usr/local/libexec/generate_production_launch_manifest.py
        COPY --chown=0:0 --chmod=0400 preflight.py /opt/serverware/release/scripts/preflight.py
        COPY --chown=0:0 --chmod=0400 runner.py /opt/serverware/release/scripts/runner.py
        COPY --chown=0:0 --chmod=0500 fixture_driver.py /usr/local/libexec/fixture_driver.py
        COPY --from=hostile-build --chown=0:0 --chmod=0555 /hostile.so /opt/serverware/hostile/hostile.so
        RUN set -eu; \\
            mkdir -p /etc/serverware \\
                /opt/serverware/release/python/bin \\
                /opt/serverware/release/python/lib/python3.12 \\
                /opt/serverware/release/evidence \\
                /opt/serverware/hostile/python \\
                /opt/serverware/hostile/python-home \\
                /var/lib/serverware/production-proof; \\
            cp /usr/local/bin/python3.12 /opt/serverware/release/python/bin/python3; \\
            cp /usr/local/lib/libpython3.12.so.1.0 /opt/serverware/release/python/lib/libpython3.12.so.1.0; \\
            cp -RL /usr/local/lib/python3.12/. /opt/serverware/release/python/lib/python3.12/; \\
            rm -rf /opt/serverware/release/python/lib/python3.12/site-packages \\
                /opt/serverware/release/python/lib/python3.12/ensurepip \\
                /opt/serverware/release/python/lib/python3.12/idlelib \\
                /opt/serverware/release/python/lib/python3.12/tkinter \\
                /opt/serverware/release/python/lib/python3.12/__pycache__; \\
            find /opt/serverware/release/python/lib/python3.12 -type d -exec chmod 0755 {{}} +; \\
            find /opt/serverware/release/python/lib/python3.12 -type f -exec chmod 0444 {{}} +; \\
            chown -R 0:0 /opt/serverware /var/lib/serverware/production-proof; \\
            chmod 0500 /opt/serverware/release/python/bin/python3; \\
            chmod 0444 /opt/serverware/release/python/lib/libpython3.12.so.1.0; \\
            chmod 0700 /var/lib/serverware/production-proof; \\
            printf 'services: {{}}\\n' > /opt/serverware/release/docker-compose.production.yml; \\
            chmod 0444 /opt/serverware/release/docker-compose.production.yml; \\
            printf 'SERVERWARE_TEST=1\\n' > /etc/serverware/production-readiness.env; \\
            chmod 0400 /etc/serverware/production-readiness.env; \\
            for name in {names}; do \\
                printf '{{"fixture":true}}\\n' > "/opt/serverware/release/evidence/$name.json"; \\
                chmod 0444 "/opt/serverware/release/evidence/$name.json"; \\
            done; \\
            printf '%s\\n' 'open("/var/lib/serverware/production-proof/hostile-site-ran", "w").write("hostile site executed\\n")' \\
                > /opt/serverware/hostile/python/sitecustomize.py; \\
            cp /opt/serverware/hostile/python/sitecustomize.py /usr/local/lib/python3.12/sitecustomize.py; \\
            chmod 0444 /opt/serverware/hostile/python/sitecustomize.py /usr/local/lib/python3.12/sitecustomize.py; \\
            python3 /usr/local/libexec/generate_production_launch_manifest.py \\
                --output /etc/serverware/production-release-launch.json \\
                --release-root /opt/serverware/release \\
                --state-directory /var/lib/serverware/production-proof \\
                --source-tree-digest sha256:{"a" * 64} \\
                --production-env /etc/serverware/production-readiness.env \\
                --python /opt/serverware/release/python/bin/python3 \\
                --python-import-root /opt/serverware/release/python/lib/python3.12 \\
                --python-import-root /opt/serverware/release/python/lib/python3.12/lib-dynload \\
                --preflight-script /opt/serverware/release/scripts/preflight.py \\
                --runner-script /opt/serverware/release/scripts/runner.py \\
                --compose-file /opt/serverware/release/docker-compose.production.yml \\
                {input_args} \\
                {output_args} \\
                --print-sha256 > /etc/serverware/production-release-launch.sha256; \\
            chmod 0444 /etc/serverware/production-release-launch.sha256; \\
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


def write_context(context: Path) -> None:
    shutil.copyfile(LAUNCHER, context / "serverware-production-launcher")
    shutil.copyfile(GENERATOR, context / "generate_production_launch_manifest.py")
    for name, content in {
        "Dockerfile": dockerfile(),
        "hostile.c": HOSTILE_C,
        "preflight.py": PREFLIGHT,
        "runner.py": RUNNER,
        "fixture_driver.py": FIXTURE_DRIVER,
    }.items():
        (context / name).write_text(content, encoding="ascii")


def main() -> int:
    if not LAUNCHER.is_file():
        raise RuntimeError(f"launcher artifact is missing; run make build-production-launcher: {LAUNCHER}")
    if not os.access(LAUNCHER, os.X_OK):
        raise RuntimeError(f"launcher artifact is not executable: {LAUNCHER}")
    launcher_digest = hashlib.sha256(LAUNCHER.read_bytes()).hexdigest()
    image = f"serverware-production-launcher-adversarial:{launcher_digest[:12]}-{uuid.uuid4().hex[:8]}"
    require_success(
        run(["docker", "version", "--format", "{{.Server.Os}}/{{.Server.Arch}}"], 30),
        "Docker availability check",
    )
    try:
        with tempfile.TemporaryDirectory(prefix="serverware-launcher-adversarial-") as temporary:
            context = Path(temporary)
            write_context(context)
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
                    600,
                ),
                "adversarial fixture image build",
            )

        architecture = run(
            ["docker", "image", "inspect", "--format", "{{.Architecture}}", image],
            30,
        )
        require_success(architecture, "fixture architecture inspection")
        if architecture.stdout.strip() != "amd64":
            raise RuntimeError(f"fixture image architecture is not amd64: {architecture.stdout.strip()!r}")

        fixture = run(
            ["docker", "run", "--rm", "--platform", PLATFORM, image],
            180,
        )
        require_success(fixture, "adversarial fixture scenarios")
        print(fixture.stdout.strip())
        return 0
    finally:
        run(["docker", "image", "rm", "--force", image], 60)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError) as error:
        print(f"production launcher adversarial test error: {error}", file=sys.stderr)
        sys.exit(1)
