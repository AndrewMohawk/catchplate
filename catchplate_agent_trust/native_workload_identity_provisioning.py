"""Local request-first retained-key certificate admission, not installation.

The independently pinned issuer and genuine original CSR/PoP establish this
limited local certificate/key association. A native packet is checked only as
an exact original container; its setup, delegation, policy commitments and any
capture diagnostics are not accepted as issuance or runtime authority here.
No control-plane imports, network, key generation or system trust changes.
"""
from __future__ import annotations

from contextlib import ExitStack
import os
from pathlib import Path
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from . import native_enrollment_packet as packet_originals
from . import workload_identity_bootstrap_originals as request_originals
from . import workload_identity_originals as certificates
from . import workload_identity_provisioning as publication
from . import _workload_tls as tls
from ._workload_stream import Budget, WorkloadClientError


MAX_PACKET_BYTES = packet_originals.MAX_BYTES
MAX_REQUEST_BYTES = request_originals.MAX_REQUEST_BYTES
MAX_CERTIFICATE_BYTES = certificates.MAX_CERTIFICATE_BYTES
MAX_ORIGINAL_BYTES = 64 * 1024 * 1024
_CONSTRUCTION = object()


def _fail():
    raise WorkloadClientError("native workload local originals or certificate admission failed")


class _Lifetime:
    """Raw clock ancestor only: never calls Budget or a same-budget verifier."""

    def __init__(self):
        self._pid = os.getpid()
        self._wall = self._opening_wall = time.time_ns()
        self._mono = self._opening_mono = time.monotonic_ns()
        self._before = 1
        self._until = (1 << 63) - 1
        self._stopped = False
        self.current()

    def current(self):
        if self._stopped:
            _fail()
        self._stopped = True
        wall, mono = time.time_ns(), time.monotonic_ns()
        if (os.getpid() != self._pid or not 0 < self._wall <= wall
                or not 0 < self._mono <= mono or not self._before <= wall < self._until
                or mono >= self._opening_mono + self._until - self._opening_wall):
            _fail()
        self._wall, self._mono = wall, mono
        self._stopped = False

    def restrict(self, before, until):
        self.current()
        if type(before) is not int or type(until) is not int or before >= until:
            self._stopped = True
            _fail()
        # A genuine issuer may begin before the Unix epoch or end beyond the
        # request timestamp profile. Preserve its intersection with the already
        # admitted positive, bounded request rather than inventing a CA limit.
        before, until = max(self._before, before), min(self._until, until)
        if not 0 < before < until < 1 << 63:
            self._stopped = True
            _fail()
        self._before, self._until = before, until
        self.current()


def _expected_leaf(value, requested):
    if value is None:
        return None
    if (type(value) is not tuple or len(value) != 3
            or any(type(item) is not int for item in value)):
        _fail()
    serial, before, after = value
    if (not 1 <= serial < 1 << 159
            or not 0 < before < after <= request_originals.MAX_EPOCH_MS // 1000
            or before * 1000 < requested.created_at_epoch_ms
            or after * 1000 > requested.expires_at_epoch_ms):
        _fail()
    return value


class _NativeCertificateAdmission:
    """Same-call originals and descriptors; never an input authority carrier."""

    def __init__(self, construction, *, packet_original, request_original, issuer_original,
            packet_components, requested, retained_key, private_key, directory,
            budget, owners, lifetime):
        if construction is not _CONSTRUCTION:
            _fail()
        self.packet_original = packet_original
        self.request_original = request_original
        self.issuer_original = issuer_original
        self.packet_components = packet_components
        self.requested = requested
        self.directory = directory
        self._retained_key, self._private_key = retained_key, private_key
        self._budget, self._owners, self._lifetime = budget, owners, lifetime
        self._leaf_raw = self._leaf_expected = None
        self._spent = self._failed = False

    @property
    def selected(self):
        return {"dnsNames": list(self.requested.requested_sans[0]),
            "uris": list(self.requested.requested_sans[1])}

    def current(self):
        if self._failed:
            _fail()
        self._failed = True
        budget = self._budget
        budget.check()
        for original in (self.packet_original, self.request_original, self.issuer_original):
            original.recheck(budget)
        if self._retained_key is not None:
            self._retained_key.recheck(budget)
        self.requested.live()  # Sibling only; never Budget._scope_check.
        self._lifetime.current()
        self.directory.check(budget)
        budget.check()
        self._failed = False

    def _admit_leaf(self, raw, expected_leaf):
        self.current()
        self._failed = True
        if type(raw) is not bytes or not 1 <= len(raw) <= MAX_CERTIFICATE_BYTES:
            _fail()
        expected = _expected_leaf(expected_leaf, self.requested)
        if self._leaf_raw is not None and (raw != self._leaf_raw or expected != self._leaf_expected):
            _fail()
        # These are local requirements derived from actual public originals,
        # not a claim that trusted ingress or native runtime admission occurred.
        # The primitive independently enforces the entire exact SAN inventory.
        selectors = {"verifiedByTrustedIngress": True,
            "spkiSha256": self.requested.subject_public_key_digest,
            "issuerSpkiSha256": self.requested.issuer_spki_digest}
        leaf = certificates._leaf_for_interval(raw, self.requested.issuer_certificate,
            self.selected, self.requested.public_key, self.requested.created_at_epoch_ms,
            self.requested.expires_at_epoch_ms, selectors, self._budget)
        certificate = leaf.certificate
        before = request_originals._epoch_ns(certificate.not_valid_before_utc)
        after = request_originals._epoch_ns(certificate.not_valid_after_utc)
        if (before % 1_000_000_000 or after % 1_000_000_000
                or not self.requested.created_at_epoch_ms * 1_000_000 <= before < after
                    <= self.requested.expires_at_epoch_ms * 1_000_000
                or not 1 <= certificate.serial_number < 1 << 159
                or expected is not None and (certificate.serial_number,
                    before // 1_000_000_000, after // 1_000_000_000) != expected):
            _fail()
        self._lifetime.restrict(before, after)
        self.requested.live()
        self._budget.check()
        self._leaf_raw, self._leaf_expected = raw, expected
        self._failed = False
        self.current()
        return leaf

    def verify_leaf(self, raw, *, expected_leaf):
        """Verify before receipt retention; returns no transferable verdict."""
        self._admit_leaf(raw, expected_leaf)

    def publish(self, certificate: tls.PinnedFile, *, _expected_leaf=None) -> publication.ProvisionedIdentity:
        self.current()
        if self._spent or self._retained_key is None or self._private_key is None:
            _fail()
        self._spent = True
        try:
            budget, owners = self._budget, self._owners
            returned = tls._load_original(certificate, MAX_CERTIFICATE_BYTES, False, budget, owners)
            leaf = self._admit_leaf(returned.raw, _expected_leaf)
            # Reopen the named pinned key as well as checking the original held
            # descriptor; neither a new key nor a cached match replaces it.
            retained = publication._retained_key(self._private_key, budget, owners)
            _key(retained, self.requested, budget)
            if retained.raw != self._retained_key.raw:
                _fail()
            returned.recheck(budget)
            retained.recheck(budget)
            self.current()
            chain = (leaf.certificate.public_bytes(serialization.Encoding.PEM)
                + self.requested.issuer_certificate.certificate.public_bytes(serialization.Encoding.PEM))
            if len(chain) > tls._MAX_IDENTITY_BYTES:
                _fail()
            pin = self.directory.publish("client-certificate.pem", chain, budget)
            published = tls._load_original(pin, tls._MAX_IDENTITY_BYTES, False, budget, owners)
            if published.raw != chain:
                _fail()
            for original in (returned, retained, published):
                original.recheck(budget)
            self.current()
            return publication.ProvisionedIdentity(pin, self._private_key)
        except BaseException:
            self._failed = True
            raise


def _key(original, requested, budget):
    tls._canonical_private_key(original.raw, budget)
    budget.check()
    private = serialization.load_pem_private_key(original.raw, password=None)
    budget.check()
    if (not isinstance(private, ec.EllipticCurvePrivateKey)
            or not isinstance(private.curve, ec.SECP256R1)
            or certificates._spki(private.public_key()) != certificates._spki(requested.public_key)):
        _fail()
    original.recheck(budget)
    requested.live()
    budget.check()


def _certificate_admission_on_budget(*, packet, issuer, request, expected_principal,
        expected_nonce, requested_sans, private_key, output_directory, budget, owners,
        _maximum_packet_bytes=MAX_PACKET_BYTES):
    """Bind actual originals once, on the caller's original deadline/owners."""
    if type(budget) is not Budget or type(owners) is not ExitStack:
        _fail()
    if type(_maximum_packet_bytes) is not int or not 1 <= _maximum_packet_bytes <= MAX_PACKET_BYTES:
        _fail()
    # Static upper bounds reserve capture/parse/leaf/chain/readback lanes before
    # their bodies. Submission additionally budgets its HTTP/protected inputs.
    if 16 * (_maximum_packet_bytes + MAX_REQUEST_BYTES + 3 * MAX_CERTIFICATE_BYTES
            + publication._PRIVATE_KEY_BYTES) + 512 * 1024 > MAX_ORIGINAL_BYTES:
        _fail()
    lifetime = _Lifetime()
    budget._bind_lifetime(budget._deadline, lifetime.current)
    tls._require_linux()
    request_originals._expectations(expected_principal, expected_nonce)
    selected = certificates._sans(requested_sans)
    for pin in (packet, issuer, request):
        tls._validate_pin(pin)
    if private_key is not None:
        tls._validate_pin(private_key)
    packet_original = tls._load_original(packet, _maximum_packet_bytes, False, budget, owners)
    issuer_original = tls._load_original(issuer, MAX_CERTIFICATE_BYTES, False, budget, owners)
    request_original = tls._load_original(request, MAX_REQUEST_BYTES, False, budget, owners)
    components = packet_originals.decode_packet_originals_on_budget(
        packet_bytes=packet_original.raw, budget=budget)
    if components.target_request_bytes != request_original.raw:
        _fail()
    requested = request_originals.verify_request_on_budget(request_bytes=request_original.raw,
        issuer_certificate_bytes=issuer_original.raw, expected_principal=expected_principal,
        expected_nonce=expected_nonce, expected_sans=selected, budget=budget)
    if components.target_issuer_certificate_der_bytes != requested.issuer_certificate.der:
        _fail()
    lifetime.restrict(requested.created_at_epoch_ms * 1_000_000,
        requested.expires_at_epoch_ms * 1_000_000)
    issuer_certificate = requested.issuer_certificate.certificate
    lifetime.restrict(request_originals._epoch_ns(issuer_certificate.not_valid_before_utc),
        request_originals._epoch_ns(issuer_certificate.not_valid_after_utc))
    requested.live()
    directory = publication._Directory(output_directory, budget, owners)
    retained = None
    if private_key is not None:
        retained = publication._retained_key(private_key, budget, owners)
        _key(retained, requested, budget)
    result = _NativeCertificateAdmission(_CONSTRUCTION, packet_original=packet_original,
        request_original=request_original, issuer_original=issuer_original,
        packet_components=components, requested=requested, retained_key=retained,
        private_key=private_key, directory=directory, budget=budget, owners=owners, lifetime=lifetime)
    result.current()
    return result


def admit_certificate(*, packet: tls.PinnedFile, issuer: tls.PinnedFile,
        request: tls.PinnedFile, private_key: tls.PinnedFile, certificate: tls.PinnedFile,
        expected_principal: str, expected_nonce: str, requested_sans: dict[str, list[str]],
        output_directory: Path | str, timeout_ms: int = 30_000,
        expected_leaf: tuple[int, int, int] | None = None) -> publication.ProvisionedIdentity:
    """Network-free direct-issuer material admission; never enrollment permission."""
    try:
        budget = Budget(timeout_ms)
        with ExitStack() as owners:
            admission = _certificate_admission_on_budget(packet=packet, issuer=issuer,
                request=request, private_key=private_key, expected_principal=expected_principal,
                expected_nonce=expected_nonce, requested_sans=requested_sans,
                output_directory=output_directory, budget=budget, owners=owners)
            result = admission.publish(certificate, _expected_leaf=expected_leaf)
            admission.current()
        budget.check()
        return result
    except Exception:
        raise WorkloadClientError(
            "native local certificate admission failed; retain any published files, no existing identity was replaced"
        ) from None
