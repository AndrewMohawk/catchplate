"""Separate explicit issuer grants over original native bootstrap material.

Native packet v2 is a data container, not a legacy signed packet. Admission
replays the dedicated cold v2 or explicit v3 bootstrap, independent grant signature, original
setup/delegation, target CSR/PoP and certificate selectors. Role-5 captures,
verifier summaries and Python success objects are never grant authority inputs.
No runtime custody, protected installation or egress claim is made here.
"""
from __future__ import annotations

from dataclasses import dataclass
import re

from catchplate import native_workload_identity_originals as originals
from catchplate import workload_identity_issuer_bootstrap as bootstrap
from catchplate_agent_trust import _workload_signed_packet as packets
from catchplate_agent_trust import workload_identity_bootstrap_originals as request_originals
from catchplate_agent_trust import workload_identity_originals as certificate_originals


SCHEMA = "catchplate.signedNativeWorkloadIdentityIssuanceAuthorization/v1"
PAYLOAD_SCHEMA = "catchplate.nativeWorkloadIdentityIssuanceAuthorization/v1"
PURPOSE = "native-workload-identity-issuance"
MAX_BYTES = 32 * 1024
MAX_PACKET_BYTES = 512 * 1024
MAX_REQUEST_BYTES = 64 * 1024
MAX_ORIGINAL_BYTES = 64 * 1024 * 1024
MAX_LIFETIME_NS = 300_000_000_000
_SERIAL = re.compile(r"[1-9a-f][0-9a-f]{0,39}\Z")
_FIELDS = frozenset({
    "schema", "sourceRevision", "purpose", "trustMode", "bootstrapDigest",
    "configurationDigest", "authorizationKeySpkiDigest", "issuerCertificateSha256",
    "issuerCertificateDerSha256", "issuerSpkiSha256", "policyHash", "releaseRecordSha256",
    "runtimeConfigurationSha256", "runtimeCaCertificateSha256", "runtimeCaSpkiSha256",
    "journalNamespace", "grantId", "packetSha256", "delegationSha256", "setupSha256",
    "policyRequirementsSha256", "identityPolicySha256", "certificateSelectorsSha256",
    "requestSha256", "csrSha256", "subjectPublicKeyInfoSha256", "principalId", "nonce",
    "selectedSans", "serialNumber", "notBeforeEpochSeconds", "notAfterEpochSeconds",
    "issuedAtEpochNs", "expiresAtEpochNs",
})


@dataclass(frozen=True, slots=True, repr=False)
class _NativeIssuanceMaterial:
    authorization_digest: str
    bootstrap_digest: str
    configuration_digest: str
    packet_digest: str
    delegation_digest: str
    setup_digest: str
    policy_requirements_digest: str
    identity_policy_digest: str
    certificate_selectors_digest: str
    request_digest: str
    csr_digest: str
    subject_public_key_digest: str
    issuer_certificate_digest: str
    issuer_certificate_der_digest: str
    issuer_spki_digest: str
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


def _preflight(authorization_bytes, bootstrap_bytes, packet_bytes, request_bytes,
        additional, certificate_bytes, work):
    bootstrap.clock.evidence.capture._SharedLedger(work)
    for raw, limit in ((authorization_bytes, MAX_BYTES), (bootstrap_bytes, bootstrap.MAX_BYTES),
            (packet_bytes, MAX_PACKET_BYTES), (request_bytes, MAX_REQUEST_BYTES)):
        bootstrap._raw(raw, limit)
    bootstrap._integer(additional, MAX_ORIGINAL_BYTES)
    leaf_size = 0
    if certificate_bytes is not None:
        bootstrap._raw(certificate_bytes, certificate_originals.MAX_CERTIFICATE_BYTES)
        leaf_size = len(certificate_bytes)
    # Retain the existing fixed journal/leaf/readback lanes. Native originals
    # additionally preflight their actual nested representations on this SAME
    # ledger. Neither forecast creates work, input bytes or a fresh allowance.
    reserve = max(additional, 8 * len(bootstrap_bytes) + 128 * 1024
        + 16 * (4096 + certificate_originals.MAX_CERTIFICATE_BYTES) + 2 * 1024 * 1024)
    need = reserve + 16 * (len(authorization_bytes) + len(packet_bytes)
        + len(request_bytes) + leaf_size) + 256 * 1024
    if need > min(MAX_ORIGINAL_BYTES, work.limits.max_input_bytes - work.metrics.input_bytes):
        bootstrap._fail()
    return reserve + 8 * len(authorization_bytes)


def _serial_and_interval(payload):
    serial_hex = payload["serialNumber"]
    if type(serial_hex) is not str or _SERIAL.fullmatch(serial_hex) is None:
        bootstrap._fail()
    serial = int(serial_hex, 16)
    if serial >= 1 << 159:
        bootstrap._fail()
    before = bootstrap._integer(payload["notBeforeEpochSeconds"], 9_223_372_036, 1)
    after = bootstrap._integer(payload["notAfterEpochSeconds"], 9_223_372_036, before + 1)
    return serial, before, after


def _admit(*, authorization_bytes, bootstrap_bytes, root_public_key, packet_bytes,
        request_bytes, live_window, transport_deadline_ns, work, _current,
        _additional_original_bytes, certificate_bytes=None):
    reserve = _preflight(authorization_bytes, bootstrap_bytes, packet_bytes, request_bytes,
        _additional_original_bytes, certificate_bytes, work)
    cold = bootstrap._verify_native_launch_on_work(bootstrap_bytes=bootstrap_bytes,
        root_public_key=root_public_key, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns, work=work, _current=_current)
    if (type(cold) is not bootstrap._IssuerMaterial
            or cold.profile not in (bootstrap.NATIVE_PROFILE, bootstrap.NATIVE_SERVICE_PROFILE)
            or type(cold.native_scope) is not bootstrap._NativeEnrollmentScope
            or cold.packet_signing_key_bytes is not None or cold.runtime_manifest_digest is not None):
        bootstrap._fail()
    scope = cold.native_scope
    opening = bootstrap._Budget(work, cold.window, cold.deadline_ns, cold.live)
    payload = bootstrap._signed(authorization_bytes, SCHEMA, PAYLOAD_SCHEMA,
        cold.authorization_public_key, MAX_BYTES, opening)
    bootstrap._object(payload, _FIELDS)
    if payload["purpose"] != PURPOSE or payload["trustMode"] != "trusted-host-local":
        bootstrap._fail()
    opening.interval(payload["issuedAtEpochNs"], payload["expiresAtEpochNs"])
    if payload["expiresAtEpochNs"] - payload["issuedAtEpochNs"] > MAX_LIFETIME_NS:
        bootstrap._fail()
    principal, nonce = payload["principalId"], payload["nonce"]
    # Preserve the request-first UTF-8 principal profile; do not borrow the
    # legacy grant's 512-byte printable-text restriction.
    request_originals._expectations(principal, nonce)
    selected = certificate_originals._sans(payload["selectedSans"])
    serial, not_before, not_after = _serial_and_interval(payload)
    kwargs = dict(packet_bytes=packet_bytes, request_bytes=request_bytes,
        issuer_certificate_bytes=cold.issuer_certificate_bytes,
        delegation_public_key_bytes=scope.delegation_public_key_bytes,
        expected_delegation_pem_sha256=scope.delegation_pem_digest,
        setup_public_key_bytes=scope.setup_public_key_bytes,
        expected_setup_pem_sha256=scope.setup_pem_digest,
        expected_principal=principal, expected_nonce=nonce, expected_sans=selected,
        work=work, live_window=opening.window, transport_deadline_ns=opening.bound,
        _current=opening.current, _additional_original_bytes=reserve)
    if certificate_bytes is None:
        admitted = originals._verify_on_work(**kwargs)
    else:
        admitted = originals._verify_certificate_on_work(certificate_bytes=certificate_bytes,
            expected_serial_number=serial, expected_not_before_epoch_seconds=not_before,
            expected_not_after_epoch_seconds=not_after, **kwargs)
    requested, delegation, setup = admitted.requested, admitted.delegation, admitted.setup
    budget = bootstrap._Budget(work, admitted.window, admitted.deadline_ns, admitted.live)
    expected_scope = {
        "release_record_sha256": scope.release_record_digest,
        "policy_hash": cold.policy_hash,
        "configuration_sha256": scope.runtime_configuration_digest,
        "runtime_ca_certificate_sha256": scope.runtime_ca_certificate_digest,
        "runtime_ca_spki_sha256": scope.runtime_ca_spki_digest,
    }
    if any(type(getattr(delegation, name)) is not type(value)
            or getattr(delegation, name) != value for name, value in expected_scope.items()):
        bootstrap._fail()
    authorizer_digest = packets._digest(bootstrap._spki(cold.authorization_public_key, budget), budget)
    expected = {
        "bootstrapDigest": cold.bootstrap_digest, "configurationDigest": cold.configuration_digest,
        "authorizationKeySpkiDigest": authorizer_digest,
        "issuerCertificateSha256": admitted.issuer_certificate_digest,
        "issuerCertificateDerSha256": requested.issuer_certificate_der_digest,
        "issuerSpkiSha256": requested.issuer_spki_digest,
        "policyHash": cold.policy_hash, "releaseRecordSha256": scope.release_record_digest,
        "runtimeConfigurationSha256": scope.runtime_configuration_digest,
        "runtimeCaCertificateSha256": scope.runtime_ca_certificate_digest,
        "runtimeCaSpkiSha256": scope.runtime_ca_spki_digest,
        "journalNamespace": cold.journal_namespace, "packetSha256": admitted.packet_digest,
        "delegationSha256": delegation.delegation_digest, "setupSha256": setup.setup_digest,
        "policyRequirementsSha256": admitted.policy_requirements_digest,
        "identityPolicySha256": admitted.identity_policy_digest,
        "certificateSelectorsSha256": admitted.certificate_selectors_digest,
        "requestSha256": requested.request_digest, "csrSha256": requested.csr_digest,
        "subjectPublicKeyInfoSha256": requested.subject_public_key_digest,
        "principalId": requested.principal_id, "nonce": requested.nonce,
    }
    if any(type(payload[name]) is not type(value) or payload[name] != value
            for name, value in expected.items()):
        bootstrap._fail()
    actual_sans = {"dnsNames": list(requested.requested_sans[0]), "uris": list(requested.requested_sans[1])}
    if selected != actual_sans:
        bootstrap._fail()
    valid_from = max(admitted.valid_from_epoch_ns, cold.attestation_interval[0])
    valid_until = min(admitted.valid_until_epoch_ns, cold.attestation_interval[1])
    if (not valid_from <= payload["issuedAtEpochNs"] < payload["expiresAtEpochNs"] <= valid_until
            or not payload["issuedAtEpochNs"] <= not_before * 1_000_000_000
            < not_after * 1_000_000_000 <= payload["expiresAtEpochNs"]):
        bootstrap._fail()
    budget.interval(payload["issuedAtEpochNs"], payload["expiresAtEpochNs"])
    budget.interval(not_before * 1_000_000_000, not_after * 1_000_000_000)
    subject_spki = bootstrap._spki(requested.public_key, budget)
    if (subject_spki in (bootstrap._spki(root_public_key, budget),
            bootstrap._spki(cold.authorization_public_key, budget), requested.issuer_certificate.spki_der)
            or requested.subject_public_key_digest in (delegation.authorizer_key_id,
                setup.authorizer_key_id, scope.runtime_ca_spki_digest)):
        bootstrap._fail()
    sans_bytes = packets._canonical(actual_sans, 8192, budget)
    grant_id = bootstrap._identifier(payload["grantId"])
    authorization_digest = packets._digest(authorization_bytes, budget)
    # Exactly the existing 17 slots: issuer slot11 remains the PEM ORIGINAL
    # digest consumed by the builder; DER has its own signed native field.
    association = (cold.journal_namespace, principal, nonce, authorization_digest, grant_id,
        cold.bootstrap_digest, cold.configuration_digest, admitted.packet_digest,
        requested.request_digest, requested.csr_digest, requested.subject_public_key_digest,
        admitted.issuer_certificate_digest, requested.issuer_spki_digest,
        serial, not_before, not_after, sans_bytes)
    budget.check()
    return _NativeIssuanceMaterial(authorization_digest, cold.bootstrap_digest,
        cold.configuration_digest, admitted.packet_digest, delegation.delegation_digest,
        setup.setup_digest, admitted.policy_requirements_digest, admitted.identity_policy_digest,
        admitted.certificate_selectors_digest, requested.request_digest, requested.csr_digest,
        requested.subject_public_key_digest, admitted.issuer_certificate_digest,
        requested.issuer_certificate_der_digest, requested.issuer_spki_digest, authorizer_digest,
        grant_id, cold.journal_namespace, principal, nonce, requested.public_key,
        requested.requested_sans, serial, not_before, not_after,
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
    """Explicit separate authorizer operation; never a CSR-triggered grant route."""
    bootstrap._raw(payload_bytes, MAX_BYTES)
    cold = bootstrap._verify_native_launch_on_work(bootstrap_bytes=bootstrap_bytes,
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
