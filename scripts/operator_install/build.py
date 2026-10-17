"""Explicit one-time image build; lifecycle operations never call this module."""
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile

from .compose import EDGE_IMAGE
from .config import InstallError

DEFAULT_TAG = "catchplate-standalone:local"
DEFAULT_CACHE_NAMESPACE = "catchplate-standalone"
RUNTIME_ROOTS = ("catchplate/", "catchplate_agent_trust/", "scripts/", "schemas/",
    "policies/", "security/", "examples/")
COMPILER_ROOTS = ("data-plane/decision-gate-rs/", "schemas/", "policies/", "ops/")
CONTEXT_ROOTS = (*RUNTIME_ROOTS, "data-plane/decision-gate-rs/", "ops/", "docker/catchplate-standalone/")
CONTEXT_FILES = {"requirements.lock", "pyproject.toml"}
MAX_CONTEXT_BYTES = 256 * 1024**2


class _MissingImage(InstallError):
    pass


def _run(argv, *, timeout=30, stdin=None):
    try:
        result = subprocess.run(argv, stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        raise InstallError("Standalone build command could not complete; no installation was started.") from None
    if result.returncode:
        if argv[:3] == ["docker", "image", "inspect"] and b"No such image:" in result.stderr:
            raise _MissingImage("A required local image is missing.")
        descriptor, path = tempfile.mkstemp(prefix="catchplate-standalone-build-error-", suffix=".log")
        with os.fdopen(descriptor, "wb") as output:
            output.write(result.stdout[-262144:] + result.stderr[-262144:])
        error = InstallError("Standalone build command failed; private diagnostics were retained, and no installation was started.")
        error.diagnostic_path = path
        raise error
    return result.stdout


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _image(reference):
    rows = json.loads(_run(["docker", "image", "inspect", reference]))
    if len(rows) != 1 or rows[0]["Os"] != "linux" or rows[0]["Architecture"] != "amd64":
        raise InstallError("standalone supports Linux/amd64 images only")
    return rows[0]


def _git(repo, *args):
    return _run(["git", "-C", str(repo), *args])


def _source(repo):
    if _git(repo, "status", "--porcelain", "--untracked-files=all"):
        raise InstallError("commit the complete source before building the standalone artifact")
    revision = _git(repo, "rev-parse", "HEAD").decode().strip()
    if not re.fullmatch("[a-f0-9]{40}", revision):
        raise InstallError("standalone source revision must be an exact Git commit")
    entries = {}
    total = 0
    for record in _git(repo, "ls-files", "--stage", "-z").split(b"\0"):
        if not record:
            continue
        header, raw_name = record.split(b"\t", 1)
        mode, blob, stage = header.decode().split()
        name = raw_name.decode("utf-8")
        if not (name in CONTEXT_FILES or name.startswith(CONTEXT_ROOTS)):
            continue
        path = repo / name
        if mode not in {"100644", "100755"} or stage != "0" or path.resolve(strict=True) != path:
            raise InstallError("standalone source must contain regular committed files")
        raw = path.read_bytes()
        total += len(raw)
        if total > MAX_CONTEXT_BYTES:
            raise InstallError("standalone build context exceeds its byte bound")
        actual = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        if actual != blob:
            raise InstallError("standalone source changed after commit")
        entries[name] = {"raw": raw, "mode": int(mode[-3:], 8), "blob": blob,
            "sha256": hashlib.sha256(raw).hexdigest()}
    return revision, entries


def _cached_proof(repo, binary, proof_path, entries):
    raw_proof = proof_path.read_bytes()
    if len(raw_proof) > 4 * 1024**2:
        raise InstallError("compiler input receipt is too large")
    proof = json.loads(raw_proof)
    raw_binary = binary.read_bytes()
    if (not 20 <= len(raw_binary) <= 128 * 1024**2 or not raw_binary.startswith(b"\x7fELF")
            or raw_binary[4:6] != b"\x02\x01" or raw_binary[18:20] != b"\x3e\x00"):
        raise InstallError("cached normal binary is not a bounded ELF artifact")
    digest = hashlib.sha256(raw_binary).hexdigest()
    files = proof["files"]
    if proof["binarySha256"] != digest or proof["actualCompilerInputs"] != len(files) or not files:
        raise InstallError("cached binary does not match its compiler input receipt")
    revision = proof["revision"]
    if not re.fullmatch("[a-f0-9]{40}", revision):
        raise InstallError("cached binary source revision is invalid")
    for name, expected in files.items():
        if name not in entries or entries[name]["sha256"] != expected["sha256"] or entries[name]["blob"] != expected["gitBlob"]:
            raise InstallError("cached binary compiler inputs differ from this source")
    diff = _git(repo, "diff", "--name-only", revision, "HEAD", "--",
        "data-plane/decision-gate-rs", "schemas", ".cargo", "Cargo.toml", "data-plane/.cargo", "data-plane/Cargo.toml")
    if diff:
        raise InstallError("cached binary crate/schema tree differs from this source")
    return raw_binary, {"ok": True, "compiledRevision": revision,
        "binarySha256": digest, "checkedCompilerInputs": len(files),
        "compilerInputReceiptDigest": _digest(raw_proof), "fullCrateAndSchemaEqual": True}


def _add(archive, name, raw, mode=0o644):
    info = tarfile.TarInfo(name)
    info.size, info.mode, info.mtime = len(raw), mode, 0
    info.uid = info.gid = 0
    archive.addfile(info, io.BytesIO(raw))


def _cache_namespace(value):
    if value is None:
        return DEFAULT_CACHE_NAMESPACE
    if not isinstance(value, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", value):
        raise InstallError("prior cache namespace must be 1-64 lowercase letters, digits or hyphens")
    return value


def _build(repo_root, tag=DEFAULT_TAG, *, cached_binary=None, compiler_inputs=None,
        cached_app_image=None, prior_cache_namespace=None):
    """Return the paired/edge immutable IDs and baked manifest, never secret data."""
    if not re.fullmatch(r"[a-z0-9][a-z0-9._:/-]{0,190}", tag) or "@" in tag:
        raise InstallError("invalid standalone output image tag")
    cached = (cached_binary is not None, compiler_inputs is not None)
    if (any(cached) and not all(cached)) or (cached_app_image is not None and not all(cached)):
        raise InstallError("cached binary and compiler receipt are required together; a cached app image is optional")
    cache_namespace = _cache_namespace(prior_cache_namespace)
    if prior_cache_namespace is not None and any(cached):
        raise InstallError("prior cache namespace applies only to a source build, not cached binary assembly")
    daemon = json.loads(_run(["docker", "info", "--format", "{{json .}}"], timeout=20))
    if daemon.get("OSType") != "linux" or daemon.get("Architecture") not in {"x86_64", "amd64"}:
        raise InstallError("standalone builds currently support a Linux/amd64 Docker daemon only")
    repo = Path(repo_root).resolve(strict=True)
    revision, entries = _source(repo)
    runtime_files = {name: value["sha256"] for name, value in entries.items()
        if name.startswith(RUNTIME_ROOTS) or name in CONTEXT_FILES}
    compiler_files = {name: value["sha256"] for name, value in entries.items()
        if name.startswith(COMPILER_ROOTS) or name == "scripts/discard_headers_parity.v1.json"}
    cache_proof = None
    binary = None
    build_args = ["--build-arg", "CARGO_CACHE_NAMESPACE=" + cache_namespace]
    if all(cached):
        binary, cache_proof = _cached_proof(repo, Path(cached_binary).resolve(strict=True),
            Path(compiler_inputs).resolve(strict=True), entries)
        build_args = ["--build-arg", "BINARY_STAGE=cached-binary"]
        if cached_app_image is not None:
            image = _image(cached_app_image)
            dependency_tag = "catchplate-standalone-dependencies:" + image["Id"].removeprefix("sha256:")
            _run(["docker", "image", "tag", image["Id"], dependency_tag])
            if _image(dependency_tag)["Id"] != image["Id"]:
                raise InstallError("cached dependency image changed")
            build_args += ["--network", "none", "--build-arg", "CACHED_APP_IMAGE=" + dependency_tag,
                "--build-arg", "DEPENDENCY_STAGE=cached-dependencies"]
    metadata = {"sourceRevision": revision, "sourceTreeDigest": _digest(_canonical(runtime_files)),
        "compilerInputsDigest": _digest(_canonical(compiler_files)),
        "expectedBinaryDigest": "sha256:" + cache_proof["binarySha256"] if cache_proof else None}
    # Only this bounded, generated context is copied; no credentials, ignored files,
    # dependency caches, Git checkout, or existing state cross the build boundary.
    with tempfile.TemporaryDirectory(prefix="catchplate-standalone-build-") as temporary:
        context = Path(temporary) / "context.tar"
        with tarfile.open(context, "w") as archive:
            for name, value in sorted(entries.items()):
                _add(archive, name, value["raw"], value["mode"])
            _add(archive, "artifact/metadata.json", _canonical(metadata))
            if binary is not None:
                _add(archive, "artifact/catchplate-decision-gate", binary, 0o555)
        with context.open("rb") as stream:
            _run(["docker", "build", "--platform", "linux/amd64", "--pull=false", "--progress", "plain",
                "--target", "standalone", "--file", "docker/catchplate-standalone/Dockerfile", "--tag", tag,
                "--build-arg", "SOURCE_REVISION=" + revision, *build_args, "-"], timeout=1800, stdin=stream)
    paired = _image(tag)
    # This tiny read-only image probe is not app initialization and cannot reach
    # any network, host state, socket, or provider.
    artifact = json.loads(_run(["docker", "run", "--rm", "--pull", "never", "--platform", "linux/amd64",
        "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--pids-limit", "32", "--cpus", "0.5", "--memory", "128m", "--memory-swap", "128m",
        paired["Id"], "artifact"], timeout=30))
    if artifact["sourceRevision"] != revision or artifact["sourceTreeDigest"] != metadata["sourceTreeDigest"]:
        raise InstallError("built image source manifest differs")
    if cache_proof and artifact["dataPlaneBinaryDigest"] != "sha256:" + cache_proof["binarySha256"]:
        raise InstallError("built cached binary manifest differs")
    try:
        edge = _image(EDGE_IMAGE)
    except _MissingImage:
        _run(["docker", "pull", "--platform", "linux/amd64", EDGE_IMAGE], timeout=180)
        edge = _image(EDGE_IMAGE)
    return {"ok": True, "operation": "build", "status": "built", "tag": tag,
        "image_id": paired["Id"], "imageId": paired["Id"], "edgeImage": EDGE_IMAGE,
        "edgeImageId": edge["Id"], "platform": "linux/amd64", "artifact": artifact,
        "compilerInvoked": not all(cached), "cachedBinaryProof": cache_proof,
        "dependencyMode": "cached-image" if cached_app_image is not None else "pinned-fresh-stage",
        "buildCacheNamespace": cache_namespace if not all(cached) else None,
        "runtimeStateChanged": False}


def build(repo_root, tag=DEFAULT_TAG, *, cached_binary=None, compiler_inputs=None,
        cached_app_image=None, prior_cache_namespace=None):
    """Public CLI boundary: report fixed diagnostics, never command/secret text."""
    try:
        return _build(repo_root, tag, cached_binary=cached_binary,
            compiler_inputs=compiler_inputs, cached_app_image=cached_app_image,
            prior_cache_namespace=prior_cache_namespace)
    except InstallError:
        raise
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        raise InstallError("Standalone build inputs or command output could not be verified; no installation was started.") from None
