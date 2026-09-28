"""Prepare independently authorized immutable public workload trust artifacts.

This is an explicit local publication, not installation, restart, CA issuance,
global authorization consumption or rollback-resistant trust rotation. A claim
and any partial output remain on failure; this module never repairs or retries
an output directory. All I/O and genuine admission share one work/deadline. An
outer watchdog is still needed to interrupt blocking native filesystem/crypto.
"""
from __future__ import annotations

from contextlib import ExitStack
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

from serverware import authority_successor_execution_window as windows
from serverware import workload_identity_trust_authorization as authorization
from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork
from serverware_agent_trust._workload_tls import PinnedFile


MAX_METADATA_BYTES = 64 * 1024
_CAPS = (128 * 1024, 16 * 1024, 64 * 1024, 64 * 1024, 64 * 1024)
_ADDITIONAL_RESERVATION_BYTES = 8 * sum(_CAPS) + 128 * 1024
_TOTAL_RESERVATION_BYTES = 16 * sum(_CAPS) + 256 * 1024
_NAMES = ("authorization.json", "authorizer-public-key.pem", "issuer-certificate.pem",
    "client-ca-bundle.pem", "principals.json", "publication.claim", "publication.json")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CHUNK = 16 * 1024


class WorkloadIdentityTrustPublicationError(ValueError):
    """Safe refusal: no error exposes original bodies or implies rollback."""


def _fail():
    raise WorkloadIdentityTrustPublicationError(
        "Trust publication did not complete. A claim or public artifacts may remain; "
        "do not retry, overwrite or treat them as installed runtime trust.")


def _path(value, work):
    if not isinstance(value, (str, Path)):
        _fail()
    raw = os.fspath(value)
    if type(raw) is not str or not 1 <= len(raw) <= 4096:
        _fail()
    work.prepare_utf8(raw)
    if (len(raw.encode("utf-8")) > 4096 or not raw.startswith("/") or "\x00" in raw
            or str(Path(raw)) != raw or any(part in {"", ".", ".."} for part in raw.split("/")[1:])):
        _fail()
    return raw, tuple(raw.split("/")[1:])


def _pin(value, work):
    if type(value) is not PinnedFile or type(value.sha256) is not str:
        _fail()
    path, parts = _path(value.path, work)
    work.prepare_utf8(value.sha256)
    if _DIGEST.fullmatch(value.sha256) is None or value.sha256 == "sha256:" + "0" * 64:
        _fail()
    return path, parts


def _directory_identity(value, *, final=False):
    if (not stat.S_ISDIR(value.st_mode) or value.st_uid not in {0, os.geteuid()}
            or value.st_mode & 0o022
            or final and (value.st_uid != os.geteuid() or stat.S_IMODE(value.st_mode) != 0o700)):
        _fail()
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid)


def _open_directory(parts, current):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    current()
    descriptor = os.open("/", flags)
    try:
        current(); _directory_identity(os.fstat(descriptor)); current()
        for component in parts:
            current()
            child = os.open(component, flags, dir_fd=descriptor)
            previous, descriptor = descriptor, child
            os.close(previous)
            current(); _directory_identity(os.fstat(descriptor)); current()
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_file(parts, current):
    parent = _open_directory(parts[:-1], current)
    try:
        current()
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
            | os.O_NONBLOCK, dir_fd=parent)
        try:
            current()
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise
    finally:
        os.close(parent)


def _file_metadata(value, maximum, *, published=False):
    if (not stat.S_ISREG(value.st_mode) or value.st_uid not in {0, os.geteuid()}
            or value.st_nlink != 1 or value.st_mode & 0o077
            or not 1 <= value.st_size <= maximum
            or published and (value.st_uid != os.geteuid() or stat.S_IMODE(value.st_mode) != 0o400)):
        _fail()
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
        value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _read(descriptor, maximum, work, current):
    current(); os.lseek(descriptor, 0, os.SEEK_SET); current()
    chunks, total = [], 0
    while True:
        count = min(_CHUNK, maximum + 1 - total)
        work.charge(input_bytes=count)
        current(); chunk = os.read(descriptor, count); current()
        if not chunk:
            break
        total += len(chunk)
        if total > maximum:
            _fail()
        chunks.append(chunk)
    work.charge(input_bytes=total)
    return b"".join(chunks)


def _digest(raw, work):
    work.charge(hashes=1, input_bytes=len(raw))
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _same_bytes(actual, expected, work):
    work.charge(input_bytes=len(actual) + len(expected))
    if actual != expected:
        _fail()


@dataclass(frozen=True, slots=True, repr=False)
class _Original:
    descriptor: int
    parts: tuple[str, ...]
    pin: PinnedFile
    raw: bytes
    metadata: tuple[int, ...]
    published: bool = False

    def check(self, work, current):
        current()
        if _file_metadata(os.fstat(self.descriptor), len(self.raw), published=self.published) != self.metadata:
            _fail()
        observed = _read(self.descriptor, len(self.raw), work, current)
        _same_bytes(observed, self.raw, work)
        if _file_metadata(os.fstat(self.descriptor), len(self.raw), published=self.published) != self.metadata:
            _fail()
        named = _open_file(self.parts, current)
        try:
            current()
            if _file_metadata(os.fstat(named), len(self.raw), published=self.published) != self.metadata:
                _fail()
            current()
        finally:
            os.close(named)


def _load(pin, maximum, work, current, owners):
    _, parts = _pin(pin, work)
    descriptor = _open_file(parts, current)
    owners.callback(os.close, descriptor)
    current()
    before = _file_metadata(os.fstat(descriptor), maximum)
    raw = _read(descriptor, before[6], work, current)
    after = _file_metadata(os.fstat(descriptor), maximum)
    work.charge(input_bytes=2 * len(raw))
    if (before != after or len(raw) != before[6] or _digest(raw, work) != pin.sha256
            or b"PRIVATE KEY" in raw.upper()):
        _fail()
    result = _Original(descriptor, parts, pin, raw, after)
    result.check(work, current)
    return result


class _Directory:
    def __init__(self, path, work, current, owners):
        self.path, self.parts = _path(path, work)
        self.descriptor = _open_directory(self.parts, current)
        owners.callback(os.close, self.descriptor)
        current()
        self.identity = _directory_identity(os.fstat(self.descriptor), final=True)
        fcntl.flock(self.descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        current(); self.check(current)
        # One bounded observation: an existing claim, artifact or unrelated
        # entry refuses before publication; no directory-wide inventory is read.
        current()
        with os.scandir(self.descriptor) as entries:
            if next(entries, None) is not None:
                _fail()
        current()

    def check(self, current):
        current()
        if _directory_identity(os.fstat(self.descriptor), final=True) != self.identity:
            _fail()
        named = _open_directory(self.parts, current)
        try:
            current()
            if _directory_identity(os.fstat(named), final=True) != self.identity:
                _fail()
            current()
        finally:
            os.close(named)

    def publish(self, name, raw, work, current, owners):
        if name not in _NAMES or type(raw) is not bytes or not 1 <= len(raw) <= 128 * 1024:
            _fail()
        self.check(current)
        # The fixed name appears first and is never removed on any failure.
        # Mode 0400 is a prepared-public-artifact permission, not installation
        # for a different runtime UID or an immutable-filesystem guarantee.
        descriptor = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL
            | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400, dir_fd=self.descriptor)
        owners.callback(os.close, descriptor)
        current()
        offset = 0
        while offset < len(raw):
            amount = min(_CHUNK, len(raw) - offset)
            work.charge(input_bytes=2 * amount)
            current(); count = os.write(descriptor, raw[offset:offset + amount]); current()
            if not 1 <= count <= amount:
                _fail()
            offset += count
        current(); os.fsync(descriptor); current()
        _same_bytes(_read(descriptor, len(raw), work, current), raw, work)
        current(); os.fsync(self.descriptor); current()
        self.check(current)
        metadata = _file_metadata(os.fstat(descriptor), len(raw), published=True)
        if metadata[6] != len(raw):
            _fail()
        pin = PinnedFile(self.path + "/" + name, _digest(raw, work))
        result = _Original(descriptor, self.parts + (name,), pin, raw, metadata, True)
        result.check(work, current)
        return result


def _encode(value, work):
    size, _ = work.prepare_encoding(value)
    if not 1 <= size <= MAX_METADATA_BYTES:
        _fail()
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False).encode("ascii")
    if len(raw) != size:
        _fail()
    return raw


def _file_description(original):
    return {"path": os.fspath(original.pin.path), "sha256": original.pin.sha256,
        "byteCount": len(original.raw)}


def publish_trust(*, authorization_original: PinnedFile, authorizer: PinnedFile,
        issuer: PinnedFile, bundle: PinnedFile, principals: PinnedFile,
        destination: Path | str, expected_deployment_id: str,
        expected_runtime_binary_sha256: str, expected_server_certificate_spki_sha256: str,
        expected_policy_hash: str, timeout_ms: int = 30000) -> bytes:
    """Return bounded public receipt JSON after exact publication/readback.

    Pins are independent operator inputs, never discovered from authorization
    bytes, the publication receipt, or an issuance response. The result is not
    a capability accepted by the actual runtime trust verifier.
    """
    try:
        if (sys.platform != "linux" or type(timeout_ms) is not int or not 1 <= timeout_ms <= 30000
                or _CAPS != (authorization.MAX_BYTES, authorization.MAX_KEY_BYTES,
                    authorization.MAX_ISSUER_BYTES, authorization.MAX_BUNDLE_BYTES,
                    authorization.MAX_PRINCIPALS_BYTES)
                or _TOTAL_RESERVATION_BYTES > authorization.MAX_ORIGINAL_BYTES):
            _fail()
        work = _ValidationWork(QueryReadValidationLimits())
        window, bound = authorization._construction_on_work(work)
        window = windows._narrow(window, deadline_epoch_ns=window[0] + timeout_ms * 1_000_000,
            maximum_lifetime_ns=timeout_ms * 1_000_000, maximum_clock_skew_ns=0)
        base = authorization._Budget(work, window, min(bound, window[4]), None)
        current = base.current
        pins = (authorization_original, authorizer, issuer, bundle, principals)
        for pin in pins:
            _pin(pin, work)
        _path(destination, work)
        # All original, verifier, publication/readback and public result
        # representations are reserved before original body one. A's eightfold
        # actual capture plus 128 KiB fits the other half of this same total.
        if (_ADDITIONAL_RESERVATION_BYTES + 8 * sum(_CAPS) + 128 * 1024
                != _TOTAL_RESERVATION_BYTES
                or _TOTAL_RESERVATION_BYTES > work.limits.max_input_bytes - work.metrics.input_bytes):
            _fail()
        with ExitStack() as owners:
            originals = tuple(_load(pin, maximum, work, current, owners)
                for pin, maximum in zip(pins, _CAPS))
            material = authorization._verify_on_work(
                authorization_bytes=originals[0].raw, authorizer_public_key_bytes=originals[1].raw,
                issuer_certificate_bytes=originals[2].raw, bundle_bytes=originals[3].raw,
                expected_principals_bytes=originals[4].raw,
                expected_deployment_id=expected_deployment_id,
                expected_runtime_binary_sha256=expected_runtime_binary_sha256,
                expected_server_certificate_spki_sha256=expected_server_certificate_spki_sha256,
                expected_policy_hash=expected_policy_hash, work=work, live_window=window,
                transport_deadline_ns=base.bound, _current=current,
                _additional_original_bytes=_ADDITIONAL_RESERVATION_BYTES)
            current = material.live
            current()
            directory = _Directory(destination, work, current, owners)

            def recheck():
                for original in originals:
                    original.check(work, current)
                directory.check(current)
                current()

            recheck()
            claim = _encode({"schema": "serverware.workloadIdentityTrustPublicationClaim/v1",
                "authorizationDigest": material.authorization_digest,
                "authorizerSha256": authorizer.sha256,
                "deploymentId": material.deployment_id,
                "configurationDigest": material.configuration_digest,
                "bundleSha256": material.bundle_digest,
                "issuerSpkiSha256": material.issuer_spki_digest,
                "principalsSha256": principals.sha256}, work)
            published = {"publication.claim": directory.publish("publication.claim", claim, work, current, owners)}
            for name, original in zip(_NAMES[:5], originals):
                recheck()
                published[name] = directory.publish(name, original.raw, work, current, owners)
            # Suggestions preserve the independently supplied authorizer PEM
            # pin. They are neither shell code nor installation authority.
            suggestions = {
                "SERVERWARE_WORKLOAD_IDENTITY_TRUST_AUTHORIZATION": published["authorization.json"].pin.path,
                "SERVERWARE_WORKLOAD_IDENTITY_TRUST_AUTHORIZER_PUBLIC_KEY": published["authorizer-public-key.pem"].pin.path,
                "SERVERWARE_WORKLOAD_IDENTITY_TRUST_AUTHORIZER_SHA256": authorizer.sha256,
                "SERVERWARE_WORKLOAD_IDENTITY_TRUST_DEPLOYMENT_ID": expected_deployment_id,
                "SERVERWARE_PROXY_CLIENT_CA_BUNDLE": published["client-ca-bundle.pem"].pin.path,
            }
            receipt = {"schema": "serverware.workloadIdentityTrustPublication/v1",
                "deploymentId": material.deployment_id, "configurationDigest": material.configuration_digest,
                "installed": False, "restarted": False, "runtimeAdmitted": False,
                "files": {name: _file_description(value) for name, value in published.items()},
                "startupSuggestions": suggestions}
            encoded = _encode(receipt, work)
            recheck()
            manifest = directory.publish("publication.json", encoded, work, current, owners)
            for original in (*published.values(), manifest):
                original.check(work, current)
            recheck()
            receipt["publicationReceipt"] = _file_description(manifest)
            result = _encode(receipt, work)
            current()
        # Normal descriptor/lock cleanup completes before public pins return;
        # the genuine original admission's nonrenewing clock guard survives it.
        current()
        return result
    except WorkloadIdentityTrustPublicationError:
        raise
    except Exception:
        _fail()
