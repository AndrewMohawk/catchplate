"""Separate signed issuance grants joined to genuine packet and P-256 originals.

No preverified request/material parameter is an authority input. Each admission
replays the independent root bootstrap, authorizer signature, packet signature,
CSR and request proof. The packet's CA-install capability is never returned or
journaled. Returned scalar associations are only for the private issuer owner.
"""
from __future__ import annotations

from dataclasses import dataclass
import re

from serverware import workload_identity_issuer_bootstrap as bootstrap
from serverware_agent_trust import _workload_signed_packet as packets
from serverware_agent_trust import workload_identity_originals as originals


SCHEMA = "serverware.signedWorkloadIdentityIssuanceAuthorization/v1"
PAYLOAD_SCHEMA = "serverware.workloadIdentityIssuanceAuthorization/v1"
MAX_BYTES = 32 * 1024
MAX_PACKET_BYTES = 8 * 1024 * 1024
MAX_REQUEST_BYTES = 64 * 1024
MAX_ORIGINAL_BYTES = 64 * 1024 * 1024
_SERIAL = re.compile(r"[1-9a-f][0-9a-f]{0,39}\Z")
_FIELDS = frozenset({
    "schema", "sourceRevision", "purpose", "trustMode", "bootstrapDigest",
    "configurationDigest", "authorizationKeySpkiDigest", "issuerCertificateSha256",
    "issuerSpkiSha256", "packetSigningKeySha256", "policyHash", "runtimeManifestDigest",
    "journalNamespace", "grantId", "packetSha256", "requestSha256", "csrSha256",
    "subjectPublicKeyInfoSha256", "principalId", "nonce", "selectedSans", "serialNumber",
    "notBeforeEpochSeconds", "notAfterEpochSeconds", "issuedAtEpochNs", "expiresAtEpochNs",
})


@dataclass(frozen=True, slots=True, repr=False)
class _IssuanceMaterial:
    authorization_digest: str
    bootstrap_digest: str
    configuration_digest: str
    packet_digest: str
    request_digest: str
    csr_digest: str
    subject_public_key_digest: str
    issuer_certificate_digest: str
    issuer_spki_digest: str
    packet_signing_key_digest: str
    authorization_key_digest: str
    grant_id: str
    journal_namespace: str
    principal_id: str
    nonce: str
    public_key: object
    selected_sans: tuple
    serial_number: int
    not_before_epoch_seconds: int
    not_after_epoch_seconds: int
    window: tuple
    deadline_ns: int
    live: object
    association: tuple


def _text(value):
    if (type(value) is not str or not 1 <= len(value) <= 512
            or any(ord(char) < 32 or ord(char) == 127 for char in value)
            or len(value.encode("utf-8")) > 512):
        bootstrap._fail()
    return value


def _preflight(authorization_bytes, bootstrap_bytes, packet_bytes, request_bytes,
        additional, certificate_bytes):
    for raw, limit in ((authorization_bytes, MAX_BYTES),
            (bootstrap_bytes, bootstrap.MAX_BYTES), (packet_bytes, MAX_PACKET_BYTES),
            (request_bytes, MAX_REQUEST_BYTES)):
        bootstrap._raw(raw, limit)
    bootstrap._integer(additional, MAX_ORIGINAL_BYTES)
    # The caller reserves cold originals and fixed journal/leaf lanes before
    # reading request body one. Eight actual request representations cover the
    # bounded packet decode/canonical/hash and the simultaneous first/readback
    # admissions; no new allowance is created here.
    cold_and_fixed = max(additional, 8 * len(bootstrap_bytes) + 128 * 1024
        + 16 * (4096 + originals.MAX_CERTIFICATE_BYTES) + 2 * 1024 * 1024)
    if cold_and_fixed + 8 * (len(authorization_bytes) + len(packet_bytes) + len(request_bytes)) > MAX_ORIGINAL_BYTES:
        bootstrap._fail()
    if certificate_bytes is not None:
        bootstrap._raw(certificate_bytes, originals.MAX_CERTIFICATE_BYTES)


def _admit(*, authorization_bytes, bootstrap_bytes, root_public_key, packet_bytes,
        request_bytes, live_window, transport_deadline_ns, work, _current,
        _additional_original_bytes, certificate_bytes=None):
    _preflight(authorization_bytes, bootstrap_bytes, packet_bytes, request_bytes,
        _additional_original_bytes, certificate_bytes)
    cold = bootstrap._verify_on_work(bootstrap_bytes=bootstrap_bytes,
        root_public_key=root_public_key, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns, work=work, _current=_current)
    budget = bootstrap._Budget(work, cold.window, cold.deadline_ns, cold.live)
    p = bootstrap._signed(authorization_bytes, SCHEMA, PAYLOAD_SCHEMA,
        cold.authorization_public_key, MAX_BYTES, budget)
    bootstrap._object(p, _FIELDS)
    if p["purpose"] != "workload-identity-issuance" or p["trustMode"] != "trusted-host-local":
        bootstrap._fail()
    budget.interval(p["issuedAtEpochNs"], p["expiresAtEpochNs"])
    if p["expiresAtEpochNs"] - p["issuedAtEpochNs"] > 900_000_000_000:
        bootstrap._fail()
    principal, nonce = _text(p["principalId"]), _text(p["nonce"])
    requested = originals.verify_request_originals(packet_bytes=packet_bytes,
        packet_signing_key_bytes=cold.packet_signing_key_bytes,
        issuer_certificate_bytes=cold.issuer_certificate_bytes, request_bytes=request_bytes,
        expected_principal=principal, expected_nonce=nonce, budget=budget)
    binding = requested.binding
    budget.interval(binding["issuedAtEpochMs"] * 1_000_000,
        binding["expiresAtEpochMs"] * 1_000_000)
    authorizer_digest = packets._digest(bootstrap._spki(cold.authorization_public_key, budget), budget)
    expected = {"bootstrapDigest": cold.bootstrap_digest,
        "configurationDigest": cold.configuration_digest,
        "authorizationKeySpkiDigest": authorizer_digest,
        "issuerCertificateSha256": binding["issuerCertificateSha256"],
        "issuerSpkiSha256": binding["issuerSpkiSha256"],
        "packetSigningKeySha256": binding["packetSigningKeySha256"],
        "policyHash": cold.policy_hash, "runtimeManifestDigest": cold.runtime_manifest_digest,
        "journalNamespace": cold.journal_namespace, "packetSha256": binding["packetSha256"],
        "requestSha256": requested.request_digest, "csrSha256": requested.csr_digest,
        "subjectPublicKeyInfoSha256": requested.subject_public_key_digest}
    if (any(type(p[name]) is not type(value) or p[name] != value for name, value in expected.items())
            or requested.policy_hash != cold.policy_hash
            or requested.runtime_manifest_digest != cold.runtime_manifest_digest):
        bootstrap._fail()
    selected = {"dnsNames": list(requested.selected_sans[0]), "uris": list(requested.selected_sans[1])}
    if p["selectedSans"] != selected:
        bootstrap._fail()
    sans_bytes = packets._canonical(selected, 8192, budget)
    grant_id = bootstrap._identifier(p["grantId"])
    serial_hex = p["serialNumber"]
    if type(serial_hex) is not str or _SERIAL.fullmatch(serial_hex) is None:
        bootstrap._fail()
    serial = int(serial_hex, 16)
    if serial >= 1 << 159:
        bootstrap._fail()
    not_before = bootstrap._integer(p["notBeforeEpochSeconds"], 253402300799, 1)
    not_after = bootstrap._integer(p["notAfterEpochSeconds"], 253402300799, not_before + 1)
    issuer = requested.issuer_certificate.certificate
    if (not_before * 1000 < binding["issuedAtEpochMs"]
            or not_after * 1000 > binding["expiresAtEpochMs"]
            or not_before < int(issuer.not_valid_before_utc.timestamp())
            or not_after > int(issuer.not_valid_after_utc.timestamp())
            or not_after * 1_000_000_000 > p["expiresAtEpochNs"]):
        bootstrap._fail()
    budget.interval(not_before * 1_000_000_000, not_after * 1_000_000_000)
    public_spki = originals._spki(requested.public_key)
    if public_spki in (bootstrap._spki(root_public_key, budget),
            bootstrap._spki(cold.authorization_public_key, budget),
            requested.issuer_certificate.spki_der):
        bootstrap._fail()
    if certificate_bytes is not None:
        leaf = originals._leaf(certificate_bytes, requested.issuer_certificate, selected,
            requested.public_key, binding, requested.selectors, budget).certificate
        if (leaf.serial_number != serial
                or int(leaf.not_valid_before_utc.timestamp()) != not_before
                or int(leaf.not_valid_after_utc.timestamp()) != not_after):
            bootstrap._fail()
    authorization_digest = packets._digest(authorization_bytes, budget)
    association = (cold.journal_namespace, principal, nonce, authorization_digest, grant_id,
        cold.bootstrap_digest, cold.configuration_digest, binding["packetSha256"],
        requested.request_digest, requested.csr_digest, requested.subject_public_key_digest,
        binding["issuerCertificateSha256"], binding["issuerSpkiSha256"], serial,
        not_before, not_after, sans_bytes)
    budget.check()
    return _IssuanceMaterial(authorization_digest, cold.bootstrap_digest,
        cold.configuration_digest, binding["packetSha256"], requested.request_digest,
        requested.csr_digest, requested.subject_public_key_digest,
        binding["issuerCertificateSha256"], binding["issuerSpkiSha256"],
        binding["packetSigningKeySha256"], authorizer_digest, grant_id,
        cold.journal_namespace, principal, nonce, requested.public_key,
        requested.selected_sans, serial, not_before, not_after,
        budget.window, budget.bound, budget.current, association)


def _verify_on_work(*, authorization_bytes, bootstrap_bytes, root_public_key,
        packet_bytes, request_bytes, live_window, transport_deadline_ns, work,
        _current=None, _additional_original_bytes=0):
    return _admit(authorization_bytes=authorization_bytes, bootstrap_bytes=bootstrap_bytes,
        root_public_key=root_public_key, packet_bytes=packet_bytes, request_bytes=request_bytes,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns, work=work,
        _current=_current, _additional_original_bytes=_additional_original_bytes)


def _verify_certificate_on_work(*, certificate_bytes, authorization_bytes,
        bootstrap_bytes, root_public_key, packet_bytes, request_bytes, live_window,
        transport_deadline_ns, work, _current=None, _additional_original_bytes=0):
    return _admit(authorization_bytes=authorization_bytes, bootstrap_bytes=bootstrap_bytes,
        root_public_key=root_public_key, packet_bytes=packet_bytes, request_bytes=request_bytes,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns, work=work,
        _current=_current, _additional_original_bytes=_additional_original_bytes,
        certificate_bytes=certificate_bytes)


def _produce_on_work(*, payload_bytes, authorization_private_key, bootstrap_bytes,
        root_public_key, packet_bytes, request_bytes, live_window, transport_deadline_ns,
        work, _current=None, _additional_original_bytes=0):
    """Explicit authorizer operation, never a packet/CSR-driven grant service."""
    cold = bootstrap._verify_on_work(bootstrap_bytes=bootstrap_bytes,
        root_public_key=root_public_key, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns, work=work, _current=_current)
    budget = bootstrap._Budget(work, cold.window, cold.deadline_ns, cold.live)
    raw = bootstrap._produce(payload_bytes, SCHEMA, PAYLOAD_SCHEMA,
        authorization_private_key, cold.authorization_public_key, MAX_BYTES, budget)
    admitted = _verify_on_work(authorization_bytes=raw, bootstrap_bytes=bootstrap_bytes,
        root_public_key=root_public_key, packet_bytes=packet_bytes, request_bytes=request_bytes,
        live_window=budget.window, transport_deadline_ns=budget.bound, work=work,
        _current=budget.current, _additional_original_bytes=_additional_original_bytes)
    admitted.live()
    return raw
