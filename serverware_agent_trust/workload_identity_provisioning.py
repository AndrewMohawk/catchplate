"""Local, packet-bound workload CSR preparation and direct-issuer admission.

A signed request proves possession, not issuance authority. Issuer trust and
packet-signing trust are independently pinned inputs; neither is discovered
from a reply. No network, CA-install token, self-issuer or key export exists.
The initial profile is SAN-authorized fresh P-256 keys and one direct issuing
CA, not a general certificate path builder or a SPIFFE lifecycle service.
Keys are software-held local PKCS#8 originals, not HSM custody or a memory-erasure
guarantee. Native crypto/filesystem calls still require an outer watchdog.
"""
from __future__ import annotations

import base64
from contextlib import ExitStack
from dataclasses import dataclass
import os
from pathlib import Path
import secrets
import stat
import time

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from . import _workload_signed_packet as packets
from . import _workload_tls as tls
from ._workload_stream import Budget, WorkloadClientError
from .workload_transport import validate_mtls_identity
from .workload_identity_originals import (
    REQUEST_SCHEMA, PAYLOAD_SCHEMA, REQUEST_DOMAIN, MAX_REQUEST_BYTES,
    MAX_CERTIFICATE_BYTES, MAX_KEY_BYTES, MAX_CSR_BYTES, _P256_ORDER,
    _fail, _digest, _spki, _extension, _valid_now, _issuer, _selected, _names,
    _request, _leaf,
)

_PRIVATE_KEY_BYTES = 1024
_ADMISSION_CONSTRUCTION = object()


@dataclass(frozen=True, slots=True, repr=False)
class PreparedIdentity:
    """Published original descriptions, never an issuance permission."""

    request: tls.PinnedFile
    csr: tls.PinnedFile
    private_key: tls.PinnedFile


@dataclass(frozen=True, slots=True, repr=False)
class ProvisionedIdentity:
    """Direct inputs for WorkloadProxyClient's existing pinned-file interface."""

    client_certificate: tls.PinnedFile
    client_private_key: tls.PinnedFile


def _path_parts(path: Path | str) -> tuple[str, list[str]]:
    if not isinstance(path, (Path, str)):
        _fail("identity output requires an absolute directory path")
    raw = os.fspath(path)
    if (not isinstance(raw, str) or not 1 <= len(raw) <= 4096
            or len(raw.encode("utf-8")) > 4096
            or not raw.startswith("/") or "\x00" in raw or str(Path(raw)) != raw
            or any(part in {"", ".", ".."} for part in raw.split("/")[1:])):
        _fail("identity output directory is not a canonical absolute path")
    return raw, raw.split("/")[1:]


def _open_directory(parts: list[str], budget: Budget) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open("/", flags)
    try:
        for component in parts:
            budget.check()
            child = os.open(component, flags, dir_fd=descriptor)
            previous, descriptor = descriptor, child
            os.close(previous)
        budget.check()
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


class _Directory:
    def __init__(self, path: Path | str, budget: Budget, owners: ExitStack):
        self.path, self.parts = _path_parts(path)
        self.descriptor = _open_directory(self.parts, budget)
        owners.callback(os.close, self.descriptor)
        self.metadata = self._metadata(os.fstat(self.descriptor))
        self.check(budget)

    @staticmethod
    def _metadata(value: os.stat_result) -> tuple[int, ...]:
        if (not stat.S_ISDIR(value.st_mode) or value.st_uid != os.geteuid()
                or stat.S_IMODE(value.st_mode) != 0o700):
            _fail("identity output directory must be current-user-owned mode 0700")
        return value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid

    def check(self, budget: Budget) -> None:
        budget.check()
        if self._metadata(os.fstat(self.descriptor)) != self.metadata:
            _fail("identity output directory changed")
        named = _open_directory(self.parts, budget)
        try:
            if self._metadata(os.fstat(named)) != self.metadata:
                _fail("identity output directory name changed")
        finally:
            os.close(named)
        budget.check()

    def publish(self, name: str, raw: bytes, budget: Budget) -> tls.PinnedFile:
        """No overwrite; a late failure leaves the published original intact."""
        self.check(budget)
        if name not in {"preparation.claim", "private-key.pem", "request.pem",
                "request.json", "client-certificate.pem", "options-response.json",
                "submission.claim", "submission-response.json", "issued-certificate.pem"}:
            _fail("identity publication name is not source-fixed")
        temporary = ".identity-" + secrets.token_hex(16)
        descriptor = os.open(temporary, os.O_RDWR | os.O_CREAT | os.O_EXCL
            | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self.descriptor)
        try:
            offset = 0
            while offset < len(raw):
                budget.check()
                count = os.write(descriptor, raw[offset:offset + 16 * 1024])
                if count < 1:
                    _fail("identity original write did not progress")
                offset += count
            budget.check()
            os.fsync(descriptor)
            budget.check()
            if tls._read_descriptor(descriptor, len(raw), budget) != raw:
                _fail("identity original readback differs")
            self.check(budget)
            # linkat is atomic and refuses an existing destination. Neither
            # rename replacement nor deletion of a previous identity is used.
            os.link(temporary, name, src_dir_fd=self.descriptor,
                dst_dir_fd=self.descriptor, follow_symlinks=False)
            os.unlink(temporary, dir_fd=self.descriptor)
            os.fsync(self.descriptor)
            budget.check()
            metadata = os.fstat(descriptor)
            if (metadata.st_uid != os.geteuid() or metadata.st_nlink != 1
                    or stat.S_IMODE(metadata.st_mode) != 0o600
                    or not stat.S_ISREG(metadata.st_mode) or metadata.st_size != len(raw)):
                _fail("identity published original permissions or shape changed")
            named = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
                | os.O_NONBLOCK, dir_fd=self.descriptor)
            try:
                if (tls._metadata(os.fstat(named)) != tls._metadata(metadata)
                        or tls._read_descriptor(named, len(raw), budget) != raw
                        or tls._metadata(os.fstat(named)) != tls._metadata(metadata)):
                    _fail("identity published original failed exact readback")
            finally:
                os.close(named)
            self.check(budget)
            return tls.PinnedFile(self.path + "/" + name, _digest(raw))
        finally:
            os.close(descriptor)
            try:
                os.unlink(temporary, dir_fd=self.descriptor)
                os.fsync(self.descriptor)
            except FileNotFoundError:
                pass


def _common(packet, packet_signing_key, issuer, expected_principal, expected_nonce,
        budget: Budget, owners: ExitStack, *, _maximum_packet_bytes=8 * 1024 * 1024):
    tls._require_linux()
    if type(_maximum_packet_bytes) is not int or not 1 <= _maximum_packet_bytes <= 8 * 1024 * 1024:
        _fail("workload packet capture bound is invalid")
    for pin in (packet, packet_signing_key, issuer):
        tls._validate_pin(pin)
    packet_original = tls._load_original(packet, _maximum_packet_bytes, False, budget, owners)
    signing_original = tls._load_original(packet_signing_key, MAX_KEY_BYTES, False, budget, owners)
    issuer_original = tls._load_original(issuer, MAX_CERTIFICATE_BYTES, False, budget, owners)
    authenticated = packets.verify_signed_workload_packet(packet_original.raw, signing_original.raw,
        expected_principal=expected_principal, expected_nonce=expected_nonce, budget=budget)
    selectors = validate_mtls_identity(authenticated["identity"].get("mtls"))
    began_ms, began_monotonic = time.time_ns() // 1_000_000, time.monotonic()
    last_ms = began_ms

    def current():
        nonlocal last_ms
        now = time.time_ns() // 1_000_000
        if now < last_ms:
            _fail("workload provisioning clock reversed")
        packets._live(authenticated, now)
        last_ms = now

    budget._bind_lifetime(began_monotonic
        + (authenticated["expiresAtEpochMs"] - began_ms) / 1000, current)
    issuer_certificate = _issuer(issuer_original.raw, budget)
    issuer_spki = _digest(issuer_certificate.spki_der)
    if "issuerSpkiSha256" in selectors and selectors["issuerSpkiSha256"] != issuer_spki:
        _fail("independent issuer differs from the signed workload issuer constraint")
    binding = {"packetSha256": packet.sha256, "packetSigningKeySha256": packet_signing_key.sha256,
        "principalId": authenticated["principalId"], "nonce": authenticated["nonce"],
        "issuerCertificateSha256": issuer.sha256, "issuerSpkiSha256": issuer_spki,
        "issuedAtEpochMs": authenticated["issuedAtEpochMs"],
        "expiresAtEpochMs": authenticated["expiresAtEpochMs"]}
    return binding, selectors, issuer_certificate, (packet_original, signing_original, issuer_original)


def _recheck(originals, issuer_certificate, directory: _Directory, budget: Budget) -> None:
    for original in originals:
        original.recheck(budget)
    _valid_now(issuer_certificate.certificate, budget)
    directory.check(budget)
    budget.check()


def _retained_key(pin: tls.PinnedFile, budget: Budget, owners: ExitStack):
    """Existing descriptor primitives, with ownership checked before body one."""
    _path, parts = tls._validate_pin(pin)
    descriptor = tls._open_original(parts, budget)
    owners.callback(os.close, descriptor)
    budget.check()
    before = os.fstat(descriptor)
    tls._check_file(before, _PRIVATE_KEY_BYTES, True)
    if before.st_uid != os.geteuid():
        _fail("retained workload key must belong to the current process user")
    raw = tls._read_descriptor(descriptor, _PRIVATE_KEY_BYTES, budget)
    budget.check()
    after = os.fstat(descriptor)
    if (tls._metadata(before) != tls._metadata(after)
            or len(raw) != before.st_size or _digest(raw) != pin.sha256):
        _fail("retained workload key differs from its pinned original")
    original = tls._Original(descriptor, parts, pin.sha256, _PRIVATE_KEY_BYTES,
        True, tls._metadata(after), raw)
    original.recheck(budget)
    return original


def prepare_identity(*, packet: tls.PinnedFile, packet_signing_key: tls.PinnedFile,
        issuer: tls.PinnedFile, expected_principal: str, expected_nonce: str,
        selected_sans: dict[str, list[str]], output_directory: Path | str,
        timeout_ms: int = 30_000) -> PreparedIdentity:
    """Create one local key/request; partial publications are never retried."""
    try:
        budget = Budget(timeout_ms)
        with ExitStack() as owners:
            binding, selectors, issuer_certificate, originals = _common(packet, packet_signing_key,
                issuer, expected_principal, expected_nonce, budget, owners)
            selected = _selected(selected_sans, selectors)
            if "certificateSha256" in selectors or "spkiSha256" in selectors:
                _fail("fresh workload key preparation cannot satisfy a preselected leaf or key")
            directory = _Directory(output_directory, budget, owners)
            _recheck(originals, issuer_certificate, directory, budget)
            # The irreversible local claim prevents repeating key creation in
            # this directory after any uncertain or partially published result.
            claim = packets._canonical({"schema": "serverware.workloadIdentityPreparation/v1",
                **binding, "selectedSans": selected}, MAX_REQUEST_BYTES, budget)
            directory.publish("preparation.claim", claim, budget)
            budget.check()
            private = ec.generate_private_key(ec.SECP256R1())
            budget.check()
            csr = (x509.CertificateSigningRequestBuilder().subject_name(x509.Name([]))
                .add_extension(x509.SubjectAlternativeName(_names(selected)), critical=True)
                .sign(private, hashes.SHA256()))
            budget.check()
            csr_raw = csr.public_bytes(serialization.Encoding.PEM)
            if len(csr_raw) > MAX_CSR_BYTES:
                _fail("workload CSR exceeds its original bound")
            payload = {"schema": PAYLOAD_SCHEMA, **binding, "selectedSans": selected,
                "subjectPublicKeyInfoSha256": _digest(_spki(private.public_key())),
                "csr": {"pem": csr_raw.decode("ascii"), "sha256": _digest(csr_raw)}}
            unsigned = packets._canonical(payload, MAX_REQUEST_BYTES, budget)
            budget.check()
            signature = private.sign(REQUEST_DOMAIN + unsigned, ec.ECDSA(hashes.SHA256()))
            budget.check()
            r, s = utils.decode_dss_signature(signature)
            signature = utils.encode_dss_signature(r, min(s, _P256_ORDER - s))
            request_raw = packets._canonical({"schema": REQUEST_SCHEMA, "payload": payload,
                "signature": "ecdsa-p256-sha256:"
                    + base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")},
                MAX_REQUEST_BYTES, budget)
            private_raw = private.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
            if len(private_raw) > _PRIVATE_KEY_BYTES:
                _fail("workload private key exceeds its local storage bound")
            _recheck(originals, issuer_certificate, directory, budget)
            private_pin = directory.publish("private-key.pem", private_raw, budget)
            csr_pin = directory.publish("request.pem", csr_raw, budget)
            request_pin = directory.publish("request.json", request_raw, budget)
            _recheck(originals, issuer_certificate, directory, budget)
            # Re-read every final original together before returning any pins.
            _retained_key(private_pin, budget, owners).recheck(budget)
            for pin, maximum in ((csr_pin, MAX_CSR_BYTES), (request_pin, MAX_REQUEST_BYTES)):
                tls._load_original(pin, maximum, False, budget, owners).recheck(budget)
            result = PreparedIdentity(request_pin, csr_pin, private_pin)
        budget.check()
        return result
    except WorkloadClientError:
        raise
    except Exception:
        raise WorkloadClientError("local workload preparation failed; retain any published files and do not retry that directory") from None




class _CertificateAdmission:
    """One local original scope, never server issuance or externally supplied authority."""

    def __init__(self, construction, *, binding, selectors, issuer_certificate,
            originals, selected, public, private_key, directory, budget, owners):
        if construction is not _ADMISSION_CONSTRUCTION:
            _fail("workload certificate admission requires its original source scope")
        self.binding, self.selectors = binding, selectors
        self.issuer_certificate, self.originals = issuer_certificate, originals
        self.selected, self.public, self.private_key = selected, public, private_key
        self.directory, self.budget, self.owners = directory, budget, owners
        self._spent = False

    def current(self):
        _recheck(self.originals, self.issuer_certificate, self.directory, self.budget)

    def publish(self, certificate: tls.PinnedFile, *, _expected_leaf=None) -> ProvisionedIdentity:
        self.current()
        if self._spent or self.private_key is None:
            _fail("workload certificate admission is spent or options-only")
        self._spent = True
        budget, owners = self.budget, self.owners
        returned = tls._load_original(certificate, MAX_CERTIFICATE_BYTES, False, budget, owners)
        admitted_leaf = _leaf(returned.raw, self.issuer_certificate, self.selected, self.public,
            self.binding, self.selectors, budget)
        if _expected_leaf is not None:
            if (type(_expected_leaf) is not tuple or len(_expected_leaf) != 3
                    or any(type(value) is not int for value in _expected_leaf)
                    or (admitted_leaf.certificate.serial_number,
                        int(admitted_leaf.certificate.not_valid_before_utc.timestamp()),
                        int(admitted_leaf.certificate.not_valid_after_utc.timestamp())) != _expected_leaf):
                _fail("workload certificate differs from the exact submitted grant")
        # All public originals and direct trust checks still precede key bytes.
        retained = _retained_key(self.private_key, budget, owners)
        tls._canonical_private_key(retained.raw, budget)
        budget.check()
        private = serialization.load_pem_private_key(retained.raw, password=None)
        budget.check()
        if (not isinstance(private, ec.EllipticCurvePrivateKey)
                or not isinstance(private.curve, ec.SECP256R1)
                or _spki(private.public_key()) != _spki(self.public)):
            _fail("workload certificate does not match the exact retained request key")
        originals = (*self.originals, returned, retained)
        _recheck(originals, self.issuer_certificate, self.directory, budget)
        _valid_now(admitted_leaf.certificate, budget)
        # The existing client expects leaf then issuer; neither becomes system trust.
        chain = (admitted_leaf.certificate.public_bytes(serialization.Encoding.PEM)
            + self.issuer_certificate.certificate.public_bytes(serialization.Encoding.PEM))
        if len(chain) > tls._MAX_IDENTITY_BYTES:
            _fail("workload admitted chain exceeds the existing client bound")
        published = self.directory.publish("client-certificate.pem", chain, budget)
        _recheck(originals, self.issuer_certificate, self.directory, budget)
        _valid_now(admitted_leaf.certificate, budget)
        tls._load_original(published, tls._MAX_IDENTITY_BYTES, False, budget, owners).recheck(budget)
        return ProvisionedIdentity(published, self.private_key)


def _certificate_admission_on_budget(*, packet, packet_signing_key, issuer,
        expected_principal, expected_nonce, request, private_key, output_directory,
        budget, owners, _maximum_packet_bytes=8 * 1024 * 1024):
    """Authenticate local originals once on the caller's existing, unrenewed budget."""
    if type(budget) is not Budget or type(owners) is not ExitStack:
        _fail("workload admission requires the original budget and descriptor owner")
    binding, selectors, issuer_certificate, common = _common(packet, packet_signing_key,
        issuer, expected_principal, expected_nonce, budget, owners,
        _maximum_packet_bytes=_maximum_packet_bytes)
    tls._validate_pin(request)
    if private_key is not None:
        tls._validate_pin(private_key)
    requested = tls._load_original(request, MAX_REQUEST_BYTES, False, budget, owners)
    selected, public = _request(requested.raw, binding, selectors, budget)
    directory = _Directory(output_directory, budget, owners)
    result = _CertificateAdmission(_ADMISSION_CONSTRUCTION, binding=binding, selectors=selectors,
        issuer_certificate=issuer_certificate, originals=(*common, requested),
        selected=selected, public=public, private_key=private_key, directory=directory,
        budget=budget, owners=owners)
    result.current()
    return result


def admit_certificate(*, packet: tls.PinnedFile, packet_signing_key: tls.PinnedFile,
        issuer: tls.PinnedFile, expected_principal: str, expected_nonce: str,
        request: tls.PinnedFile, private_key: tls.PinnedFile, certificate: tls.PinnedFile,
        output_directory: Path | str, timeout_ms: int = 30_000) -> ProvisionedIdentity:
    """Admit one direct-issued leaf locally; this public API remains network-free."""
    try:
        budget = Budget(timeout_ms)
        with ExitStack() as owners:
            admission = _certificate_admission_on_budget(packet=packet,
                packet_signing_key=packet_signing_key, issuer=issuer,
                expected_principal=expected_principal, expected_nonce=expected_nonce,
                request=request, private_key=private_key, output_directory=output_directory,
                budget=budget, owners=owners)
            result = admission.publish(certificate)
        budget.check()
        return result
    except WorkloadClientError:
        raise
    except (InvalidSignature, UnsupportedAlgorithm):
        raise WorkloadClientError("workload request or certificate authentication failed") from None
    except Exception:
        raise WorkloadClientError("local workload certificate admission failed; no existing identity was replaced") from None
