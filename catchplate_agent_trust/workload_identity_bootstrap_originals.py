"""Request-first public CSR/PoP originals, not enrollment or issuance permission.

The caller supplies the actual independently pinned issuer original and its own
expected target identity. No packet, runtime-manifest alias, bootstrap-caller
delegation, network operation or successful verification DTO is accepted here.
All work uses the supplied original budget; the returned live check is a sibling
guard and must never be rebound as that budget's own scope callback.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import os
import time

from . import _workload_signed_packet as packets
from . import workload_identity_originals as shared
from ._workload_stream import WorkloadClientError


REQUEST_SCHEMA = "catchplate.signedWorkloadIdentityBootstrapRequest/v1"
PAYLOAD_SCHEMA = "catchplate.workloadIdentityBootstrapRequest/v1"
REQUEST_DOMAIN = PAYLOAD_SCHEMA.encode("ascii") + b"\x00"
MAX_REQUEST_BYTES = shared.MAX_REQUEST_BYTES
MAX_CSR_BYTES = shared.MAX_CSR_BYTES
MAX_CERTIFICATE_BYTES = shared.MAX_CERTIFICATE_BYTES
MAX_LIFETIME_MS = 300_000
MAX_EPOCH_MS = 9_223_372_036_854
_FIELDS = frozenset({
    "schema", "principalId", "nonce", "issuerCertificateDerSha256",
    "issuerSpkiSha256", "subjectPublicKeyInfoSha256", "requestedSans",
    "createdAtEpochMs", "expiresAtEpochMs", "csr",
})
_sans = shared._sans


def _fail(message):
    raise WorkloadClientError(message)


def _expectations(principal, nonce):
    packets._principal(principal)
    if type(nonce) is not str or packets._NONCE.fullmatch(nonce) is None:
        _fail("workload bootstrap expected nonce is invalid")


def _epoch_ns(value):
    # X.509 dates are genuine parsed originals. Integer arithmetic preserves
    # their actual bounds without floating-point timestamp rounding.
    delta = value - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return ((delta.days * 86400 + delta.seconds) * 1_000_000_000
        + delta.microseconds * 1000)


class _OriginalGuard:
    """Actual inherited budget plus sticky wall continuity; no new allowance."""

    def __init__(self, budget):
        self._budget = budget
        self._pid = os.getpid()
        self._last_ns = 0
        self._interval = None
        self._failed = False
        self.current()

    def current(self):
        if self._failed or os.getpid() != self._pid:
            self._failed = True
            _fail("workload bootstrap original owner ended")
        self._failed = True
        self._budget.check()
        inherited_current = getattr(self._budget, "current", None)
        now = inherited_current() if inherited_current is not None else time.time_ns()
        if type(now) is not int or now <= 0 or now < self._last_ns:
            _fail("workload bootstrap original clock moved backwards")
        if self._interval is not None and not self._interval[0] <= now < self._interval[1]:
            _fail("workload bootstrap request or issuer original expired")
        self._budget.check()
        self._last_ns = now
        self._failed = False
        return now

    def check(self):
        self.current()

    def charge(self, **amounts):
        self.check()
        packets._charge(self._budget, **amounts)
        self.check()

    def interval(self, created_ms, expires_ms, issuer):
        if self._interval is not None:
            _fail("workload bootstrap original interval was already retained")
        before = _epoch_ns(issuer.not_valid_before_utc)
        after = _epoch_ns(issuer.not_valid_after_utc)
        created, expires = created_ms * 1_000_000, expires_ms * 1_000_000
        if not before <= created < expires <= after:
            _fail("workload bootstrap request exceeds the actual issuer interval")
        self._interval = (created, expires)
        self.check()


@dataclass(frozen=True, slots=True, repr=False)
class _BootstrapRequestOriginals:
    principal_id: str
    nonce: str
    requested_sans: tuple
    issuer_certificate: object
    issuer_certificate_der_digest: str
    issuer_spki_digest: str
    subject_public_key_digest: str
    public_key: object
    csr_bytes: bytes
    csr_digest: str
    request_digest: str
    created_at_epoch_ms: int
    expires_at_epoch_ms: int
    live: object


def verify_request_on_budget(*, request_bytes, issuer_certificate_bytes,
        expected_principal, expected_nonce, expected_sans, budget):
    """Verify original CSR/PoP and exact expected identity, not its permission.

    The issuer DER digest is deliberately different from an independently
    pinned file's digest over PEM bytes. A claimed issuer/hash never chooses the
    trust input. Returned facts cannot replace re-admission of these originals.
    """
    try:
        guard = _OriginalGuard(budget)
        if (type(request_bytes) is not bytes or not 1 <= len(request_bytes) <= MAX_REQUEST_BYTES
                or type(issuer_certificate_bytes) is not bytes
                or not 1 <= len(issuer_certificate_bytes) <= MAX_CERTIFICATE_BYTES):
            _fail("workload bootstrap originals exceed their fixed bounds")
        _expectations(expected_principal, expected_nonce)
        expected = _sans(expected_sans)
        guard.check()
        envelope = packets._parse_packet(request_bytes, guard)
        if (set(envelope) != {"schema", "payload", "signature"}
                or envelope["schema"] != REQUEST_SCHEMA
                or type(envelope["payload"]) is not dict
                or set(envelope["payload"]) != _FIELDS
                or packets._canonical(envelope, MAX_REQUEST_BYTES, guard) != request_bytes):
            _fail("workload bootstrap request violates its closed canonical profile")
        payload = envelope["payload"]
        if (payload["schema"] != PAYLOAD_SCHEMA
                or type(payload["principalId"]) is not str
                or type(payload["nonce"]) is not str
                or payload["principalId"] != expected_principal or payload["nonce"] != expected_nonce):
            _fail("workload bootstrap target differs from independent expectations")
        selected = _sans(payload["requestedSans"])
        if selected != expected:
            _fail("workload bootstrap SANs differ from independent expectations")
        created, expires = payload["createdAtEpochMs"], payload["expiresAtEpochMs"]
        if (type(created) is not int or type(expires) is not int
                or not 0 < created < expires <= MAX_EPOCH_MS
                or expires - created > MAX_LIFETIME_MS):
            _fail("workload bootstrap original lifetime is invalid")
        issuer = shared._issuer(issuer_certificate_bytes, guard)
        guard.interval(created, expires, issuer.certificate)
        issuer_digest = packets._digest(issuer.der, guard)
        issuer_spki = packets._digest(issuer.spki_der, guard)
        if (payload["issuerCertificateDerSha256"] != issuer_digest
                or payload["issuerSpkiSha256"] != issuer_spki):
            _fail("workload bootstrap issuer differs from the pinned original")
        csr_raw, public, spki_digest, csr_digest = shared._csr(payload["csr"], selected, guard)
        if payload["subjectPublicKeyInfoSha256"] != spki_digest:
            _fail("workload bootstrap CSR key differs from its original commitment")
        shared._request_signature(envelope["signature"], payload, public, REQUEST_DOMAIN, guard)
        request_digest = packets._digest(request_bytes, guard)
        shared._valid_now(issuer.certificate, guard)
        guard.check()
        return _BootstrapRequestOriginals(expected_principal, expected_nonce,
            (tuple(selected["dnsNames"]), tuple(selected["uris"])), issuer, issuer_digest,
            issuer_spki, spki_digest, public, csr_raw, csr_digest, request_digest,
            created, expires, guard.current)
    except WorkloadClientError:
        raise
    except Exception:
        raise WorkloadClientError("workload bootstrap original verification failed") from None
