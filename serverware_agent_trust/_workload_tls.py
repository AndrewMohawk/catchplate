"""Cold, pinned TLS construction for the ordinary workload client.

Pins and local file permissions do not establish enrollment or CA authority.
No default roots, original-path TLS reload, password callback, or key export is
provided. Python/OpenSSL retain key copies; this is not HSM custody or a memory
erasure guarantee. Blocking filesystem/OpenSSL calls still need an outer
watchdog even though the shared original budget brackets their use.
"""
from __future__ import annotations

import fcntl
import hashlib
import os
import re
import ssl
import stat
import sys
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from ._workload_stream import Budget, WorkloadClientError


_MAX_CA_BYTES = 1024 * 1024
_MAX_IDENTITY_BYTES = 64 * 1024
_READ_BYTES = 16 * 1024
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CERTIFICATE = re.compile(
    rb"-----BEGIN CERTIFICATE-----\r?\n"
    rb"[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----"
)


@dataclass(frozen=True, repr=False)
class PinnedFile:
    """An independently supplied pin; construction performs no file access."""

    path: Path | str
    sha256: str

    def __repr__(self) -> str:
        return "PinnedFile(<redacted>)"


@dataclass(frozen=True, repr=False)
class TlsContexts:
    # Internal serving capabilities, not serializable/public evidence objects.
    proxy: ssl.SSLContext
    provider: ssl.SSLContext

    def __repr__(self) -> str:
        return "TlsContexts(<private contexts>)"


def _require_linux() -> None:
    os_names = (
        "O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK",
        "memfd_create", "MFD_CLOEXEC", "MFD_ALLOW_SEALING", "geteuid",
    )
    fcntl_names = (
        "F_ADD_SEALS", "F_GET_SEALS", "F_SEAL_WRITE", "F_SEAL_GROW",
        "F_SEAL_SHRINK", "F_SEAL_SEAL",
    )
    if (
        sys.platform != "linux"
        or any(not hasattr(os, name) for name in os_names)
        or any(not hasattr(fcntl, name) for name in fcntl_names)
        or os.open not in os.supports_dir_fd
    ):
        raise WorkloadClientError("bounded workload TLS requires Linux file and sealing support")


def _validate_pin(value: PinnedFile) -> tuple[str, list[str]]:
    if not isinstance(value, PinnedFile) or not isinstance(value.path, (Path, str)):
        raise WorkloadClientError("workload TLS requires pinned file descriptions")
    raw = os.fspath(value.path)
    if not isinstance(raw, str) or not 1 <= len(raw.encode("utf-8")) <= 4096:
        raise WorkloadClientError("workload TLS file path exceeds its bound")
    parts = raw.split("/")
    if (
        not raw.startswith("/")
        or "\x00" in raw
        or len(parts) < 2
        or any(part in {"", ".", ".."} for part in parts[1:])
        or str(Path(raw)) != raw
        or not isinstance(value.sha256, str)
        or _SHA256.fullmatch(value.sha256) is None
        or value.sha256 == "sha256:" + "0" * 64
    ):
        raise WorkloadClientError("workload TLS file path or SHA-256 pin is not canonical")
    return raw, parts[1:]


def _open_original(parts: list[str], budget: Budget) -> int:
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    budget.check()
    directory = os.open("/", directory_flags)
    try:
        budget.check()
        for component in parts[:-1]:
            budget.check()
            child = os.open(component, directory_flags, dir_fd=directory)
            # Transfer ownership before a budget check can raise.
            previous, directory = directory, child
            os.close(previous)
            budget.check()
        budget.check()
        descriptor = os.open(
            parts[-1],
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
            dir_fd=directory,
        )
        try:
            budget.check()
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise
    finally:
        os.close(directory)


def _metadata(value: os.stat_result) -> tuple[int, ...]:
    # Access time is intentionally excluded: reading the admitted file may
    # update it. Node identity, permissions, size and write/change times bind.
    return (
        value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
        value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns,
    )


def _check_file(value: os.stat_result, maximum: int, private: bool) -> None:
    if not stat.S_ISREG(value.st_mode) or not 1 <= value.st_size <= maximum:
        raise WorkloadClientError("workload TLS input is not a bounded nonempty regular file")
    if private and (
        value.st_uid not in {0, os.geteuid()}
        or value.st_mode & 0o077
        or value.st_nlink != 1
    ):
        raise WorkloadClientError("workload TLS private key permissions are not owner-only")


def _read_descriptor(descriptor: int, maximum: int, budget: Budget) -> bytes:
    budget.check()
    os.lseek(descriptor, 0, os.SEEK_SET)
    budget.check()
    chunks: list[bytes] = []
    total = 0
    while True:
        budget.check()
        chunk = os.read(descriptor, min(_READ_BYTES, maximum + 1 - total))
        budget.check()
        if not chunk:
            break
        total += len(chunk)
        if total > maximum:
            raise WorkloadClientError("workload TLS input exceeded its byte bound")
        chunks.append(chunk)
    return b"".join(chunks)


@dataclass(repr=False)
class _Original:
    descriptor: int
    parts: list[str]
    sha256: str
    maximum: int
    private: bool
    metadata: tuple[int, ...]
    raw: bytes

    def recheck(self, budget: Budget) -> None:
        budget.check()
        before = os.fstat(self.descriptor)
        budget.check()
        _check_file(before, self.maximum, self.private)
        if _metadata(before) != self.metadata:
            raise WorkloadClientError("workload TLS original metadata changed")
        raw = _read_descriptor(self.descriptor, self.maximum, budget)
        budget.check()
        after = os.fstat(self.descriptor)
        budget.check()
        if (
            _metadata(after) != self.metadata
            or raw != self.raw
            or "sha256:" + hashlib.sha256(raw).hexdigest() != self.sha256
        ):
            raise WorkloadClientError("workload TLS original bytes changed")
        named = _open_original(self.parts, budget)
        try:
            budget.check()
            observed = os.fstat(named)
            budget.check()
            if _metadata(observed) != self.metadata:
                raise WorkloadClientError("workload TLS original name changed")
        finally:
            os.close(named)


def _load_original(
    pin: PinnedFile, maximum: int, private: bool, budget: Budget, owners: ExitStack,
) -> _Original:
    _, parts = _validate_pin(pin)
    descriptor = _open_original(parts, budget)
    owners.callback(os.close, descriptor)
    budget.check()
    before = os.fstat(descriptor)
    budget.check()
    # This runs before the first private-key byte is read.
    _check_file(before, maximum, private)
    raw = _read_descriptor(descriptor, maximum, budget)
    budget.check()
    after = os.fstat(descriptor)
    budget.check()
    if (
        _metadata(before) != _metadata(after)
        or len(raw) != before.st_size
        or "sha256:" + hashlib.sha256(raw).hexdigest() != pin.sha256
    ):
        raise WorkloadClientError("workload TLS original does not match its immutable pin")
    original = _Original(descriptor, parts, pin.sha256, maximum, private, _metadata(after), raw)
    original.recheck(budget)
    return original


def _public_certificates(raw: bytes, budget: Budget, *, client: bool) -> str:
    budget.check()
    if b"PRIVATE KEY" in raw.upper():
        raise WorkloadClientError("workload TLS public input contains a private-key marker")
    text = raw.decode("ascii")
    matches = list(_CERTIFICATE.finditer(raw))
    position = 0
    if not matches or (client and len(matches) > 16):
        raise WorkloadClientError("workload TLS certificate inventory is empty or exceeds its bound")
    for match in matches:
        if raw[position:match.start()].strip():
            raise WorkloadClientError("workload TLS public input contains non-certificate data")
        budget.check()
        x509.load_pem_x509_certificate(match.group())
        budget.check()
        position = match.end()
    if raw[position:].strip():
        raise WorkloadClientError("workload TLS public input contains trailing data")
    return text


def _canonical_private_key(raw: bytes, budget: Budget) -> None:
    if not raw.startswith(b"-----BEGIN PRIVATE KEY-----\n"):
        raise WorkloadClientError("workload TLS key must be canonical unencrypted PKCS#8 PEM")
    budget.check()
    key = serialization.load_pem_private_key(raw, password=None)
    budget.check()
    encoded = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    budget.check()
    if encoded != raw:
        raise WorkloadClientError("workload TLS key must be canonical unencrypted PKCS#8 PEM")


def _sealed_pem(raw: bytes, budget: Budget, owners: ExitStack) -> int:
    budget.check()
    descriptor = os.memfd_create(
        "serverware-workload-tls", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING,
    )
    owners.callback(os.close, descriptor)
    budget.check()
    os.fchmod(descriptor, 0o600)
    budget.check()
    remaining = memoryview(raw)
    while remaining:
        budget.check()
        count = os.write(descriptor, remaining[:_READ_BYTES])
        budget.check()
        if count <= 0:
            raise WorkloadClientError("workload TLS sealed input write made no progress")
        remaining = remaining[count:]
    seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
    budget.check()
    fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, seals)
    budget.check()
    actual_seals = fcntl.fcntl(descriptor, fcntl.F_GET_SEALS)
    budget.check()
    metadata = os.fstat(descriptor)
    budget.check()
    if (
        actual_seals & seals != seals
        or not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size != len(raw)
        or metadata.st_uid != os.geteuid()
    ):
        raise WorkloadClientError("workload TLS input sealing failed")
    return descriptor


def _context(cadata: str, budget: Budget) -> ssl.SSLContext:
    budget.check()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    budget.check()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(["http/1.1"])
    budget.check()
    # SSLContext construction does not load system roots. Never call a default
    # context factory, load_default_certs(), or set_default_verify_paths().
    context.load_verify_locations(cadata=cadata)
    budget.check()
    if context.cert_store_stats().get("x509_ca", 0) < 1:
        raise WorkloadClientError("workload TLS trust store contains no CA certificate")
    budget.check()
    return context


def load_tls_contexts(
    *,
    proxy_ca: PinnedFile,
    client_certificate: PinnedFile,
    client_private_key: PinnedFile,
    interception_ca: PinnedFile,
    budget: Budget,
) -> TlsContexts:
    """Build distinct private contexts from one checked set of pinned bytes."""
    try:
        budget.check()
        _require_linux()
        # Validate every supplied description before reading any original.
        for pin in (proxy_ca, client_certificate, client_private_key, interception_ca):
            _validate_pin(pin)
        with ExitStack() as owners:
            proxy_original = _load_original(proxy_ca, _MAX_CA_BYTES, False, budget, owners)
            provider_original = _load_original(interception_ca, _MAX_CA_BYTES, False, budget, owners)
            certificate_original = _load_original(
                client_certificate, _MAX_IDENTITY_BYTES, False, budget, owners,
            )
            key_original = _load_original(
                client_private_key, _MAX_IDENTITY_BYTES, True, budget, owners,
            )
            proxy_pem = _public_certificates(proxy_original.raw, budget, client=False)
            provider_pem = _public_certificates(provider_original.raw, budget, client=False)
            _public_certificates(certificate_original.raw, budget, client=True)
            _canonical_private_key(key_original.raw, budget)
            proxy = _context(proxy_pem, budget)
            provider = _context(provider_pem, budget)
            certificate_fd = _sealed_pem(certificate_original.raw, budget, owners)
            key_fd = _sealed_pem(key_original.raw, budget, owners)
            budget.check()
            proxy.load_cert_chain(
                certfile=f"/proc/self/fd/{certificate_fd}",
                keyfile=f"/proc/self/fd/{key_fd}",
                password=None,
            )
            budget.check()
            # OpenSSL has checked the actual key pair. The provider context
            # intentionally never receives a client certificate or private key.
            for original in (proxy_original, provider_original, certificate_original, key_original):
                original.recheck(budget)
            result = TlsContexts(proxy=proxy, provider=provider)
        budget.check()
        return result
    except WorkloadClientError:
        raise
    except Exception:
        # Do not surface filenames, PEM contents, OpenSSL diagnostics or key
        # parser internals through the public SDK error or exception chaining.
        raise WorkloadClientError("workload TLS pinned inputs or context construction failed") from None
