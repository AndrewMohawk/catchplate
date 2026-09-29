"""Independent caller-to-target bootstrap delegation originals, not admission.

The explicit authorizer signs a closed runtime/caller/target scope. Both paths
reverify the actual request-first target CSR/PoP and independently supplied
issuer original; neither accepts a successful result as authority. Signed caller
or runtime pins are constraints, not observations of a live native connection.
There is no packet construction, network call, durable claim, issuer grant or
reachable enrollment signer here. Existing assignment semantics are unchanged.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from serverware import native_enrollment_assignment as assignment
from serverware_agent_trust import _workload_signed_packet as packets
from serverware_agent_trust import workload_identity_bootstrap_originals as bootstrap


SCHEMA = "serverware.signedNativeEnrollmentBootstrapDelegation/v1"
PAYLOAD_SCHEMA = "serverware.nativeEnrollmentBootstrapDelegation/v1"
PURPOSE = "native-enrollment-bootstrap"
SIGNATURE_DOMAIN = b"serverware/native-enrollment-bootstrap-delegation/v1\x00"
MAX_BYTES = MAX_PAYLOAD_BYTES = 32 * 1024
MAX_KEY_BYTES = assignment.MAX_KEY_BYTES
MAX_REQUEST_BYTES = bootstrap.MAX_REQUEST_BYTES
MAX_ISSUER_BYTES = bootstrap.MAX_CERTIFICATE_BYTES
MAX_ORIGINAL_BYTES = assignment.MAX_ORIGINAL_BYTES
MAX_INTERVAL_SECONDS = assignment.MAX_INTERVAL_SECONDS
MAX_EPOCH_SECONDS = assignment.MAX_EPOCH_SECONDS
MAX_PROCESSING_NS = assignment.MAX_PROCESSING_NS
MAX_JSON_DEPTH = 4
shared = assignment.shared
clock = assignment.clock
_FIELDS = frozenset({
    "apiVersion", "purpose", "authorizerKeyId", "delegationId", "releaseRecordSha256",
    "policyHash", "configurationSha256", "runtimeCaCertificateSha256",
    "runtimeCaSpkiSha256", "ingressLeafCertificateSha256", "clientTrustBundleSha256",
    "callerPrincipalId", "callerIssuerCertificateSha256", "callerIssuerSpkiSha256",
    "callerCertificateSha256", "callerSpkiSha256", "ingressHost", "serverInstanceId",
    "proxyEndpoint", "clientChallengeBase64url", "targetPrincipalId", "targetNonce",
    "targetRequestSha256", "targetCsrSha256", "targetSpkiSha256", "targetRequestedSans",
    "targetIssuerCertificateDerSha256", "targetIssuerSpkiSha256", "targetCreatedAtEpochMs",
    "targetExpiresAtEpochMs", "notBeforeUnixSeconds", "expiresAtUnixSeconds",
})
_DIGEST_FIELDS = (
    "authorizerKeyId", "releaseRecordSha256", "policyHash", "configurationSha256",
    "runtimeCaCertificateSha256", "runtimeCaSpkiSha256", "ingressLeafCertificateSha256",
    "clientTrustBundleSha256", "callerIssuerCertificateSha256", "callerIssuerSpkiSha256",
    "callerCertificateSha256", "callerSpkiSha256", "targetRequestSha256", "targetCsrSha256",
    "targetSpkiSha256", "targetIssuerCertificateDerSha256", "targetIssuerSpkiSha256",
)
_SEPARATE_KEY_FIELDS = (
    "runtimeCaSpkiSha256", "callerIssuerSpkiSha256", "callerSpkiSha256",
    "targetIssuerSpkiSha256", "targetSpkiSha256",
)


class NativeEnrollmentBootstrapDelegationError(ValueError):
    pass


def _fail():
    raise NativeEnrollmentBootstrapDelegationError("native enrollment bootstrap delegation is invalid")


def _construction_on_work(work):
    """Construct only the existing real-clock window on the supplied ledger."""
    return assignment._construction_on_work(work)


@dataclass(frozen=True, slots=True, repr=False)
class _DelegationMaterial:
    delegation_digest: str
    authorizer_key_id: str
    delegation_id: str
    release_record_sha256: str
    policy_hash: str
    configuration_sha256: str
    runtime_ca_certificate_sha256: str
    runtime_ca_spki_sha256: str
    ingress_leaf_certificate_sha256: str
    client_trust_bundle_sha256: str
    caller_principal_id: str
    caller_issuer_certificate_sha256: str
    caller_issuer_spki_sha256: str
    caller_certificate_sha256: str
    caller_spki_sha256: str
    ingress_host: str
    server_instance_id: str
    proxy_endpoint: str
    client_challenge_base64url: str
    target_principal_id: str
    target_nonce: str
    target_request_sha256: str
    target_csr_sha256: str
    target_spki_sha256: str
    target_requested_sans: tuple
    target_issuer_certificate_der_sha256: str
    target_issuer_spki_sha256: str
    target_created_at_epoch_ms: int
    target_expires_at_epoch_ms: int
    not_before_unix_seconds: int
    expires_at_unix_seconds: int
    window: tuple
    deadline_ns: int
    live: object


def _preflight(originals, additional, work, *, producing=False):
    clock.evidence.capture._SharedLedger(work)
    shared._integer(additional, MAX_ORIGINAL_BYTES)
    total = MAX_BYTES if producing else 0
    for raw, maximum in originals:
        shared._raw(raw, maximum)
        total += len(raw)
    if additional + 16 * total + 256 * 1024 > min(MAX_ORIGINAL_BYTES,
            work.limits.max_input_bytes - work.metrics.input_bytes):
        _fail()


def _decode(original, maximum, budget):
    """Bound the nested SAN arrays before decoding; grammar remains strict JSON."""
    shared._raw(original, maximum)
    budget.check()
    depth = 0
    quoted = escaped = False
    for index, byte in enumerate(original):
        if index % 1024 == 0:
            budget.check()
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (123, 91):
            depth += 1
            if depth > MAX_JSON_DEPTH:
                _fail()
        elif byte in (125, 93):
            depth -= 1
            if depth < 0:
                _fail()
    if quoted or escaped or depth:
        _fail()
    budget.charge(input_bytes=len(original))
    # Existing packet canonicalization uses ensure_ascii=True, including
    # lowercase Unicode escapes and surrogate pairs. No raw-UTF8 alternative.
    return shared._decode(original, maximum, budget)


def _payload(value, public, request_bytes, issuer_bytes, budget):
    shared._object(value, _FIELDS)
    if value["apiVersion"] != PAYLOAD_SCHEMA or value["purpose"] != PURPOSE:
        _fail()
    for field in _DIGEST_FIELDS:
        assignment._digest(value[field])
    assignment._identifier(value["delegationId"])
    assignment._identifier(value["clientChallengeBase64url"])
    assignment._ascii(value["callerPrincipalId"], 256)
    assignment._host(value["ingressHost"])
    assignment._instance(value["serverInstanceId"])
    assignment._endpoint(value["proxyEndpoint"])
    bootstrap._expectations(value["targetPrincipalId"], value["targetNonce"])
    selected = bootstrap._sans(value["targetRequestedSans"])
    created = shared._integer(value["targetCreatedAtEpochMs"], bootstrap.MAX_EPOCH_MS, 1)
    target_expires = shared._integer(value["targetExpiresAtEpochMs"], bootstrap.MAX_EPOCH_MS,
        created + 1)
    if target_expires - created > bootstrap.MAX_LIFETIME_MS:
        _fail()
    issued = shared._integer(value["notBeforeUnixSeconds"], MAX_EPOCH_SECONDS, 1)
    expires = shared._integer(value["expiresAtUnixSeconds"], MAX_EPOCH_SECONDS, issued + 1)
    if (expires - issued > MAX_INTERVAL_SECONDS
            or issued * 1000 < created or expires * 1000 > target_expires):
        _fail()
    budget.interval(issued * 1_000_000_000, expires * 1_000_000_000)
    authorizer_id = packets._digest(shared._spki(public, budget), budget)
    if value["authorizerKeyId"] != authorizer_id or any(
            value[field] == authorizer_id for field in _SEPARATE_KEY_FIELDS):
        _fail()
    # The signed delegation supplies the target expectations, never the target
    # request or a caller-provided successful verification object. The issuer
    # original remains separately selected by this API's real caller.
    target = bootstrap.verify_request_on_budget(request_bytes=request_bytes,
        issuer_certificate_bytes=issuer_bytes, expected_principal=value["targetPrincipalId"],
        expected_nonce=value["targetNonce"], expected_sans=selected, budget=budget)
    if (target.request_digest != value["targetRequestSha256"]
            or target.csr_digest != value["targetCsrSha256"]
            or target.subject_public_key_digest != value["targetSpkiSha256"]
            or target.issuer_certificate_der_digest != value["targetIssuerCertificateDerSha256"]
            or target.issuer_spki_digest != value["targetIssuerSpkiSha256"]
            or target.created_at_epoch_ms != created or target.expires_at_epoch_ms != target_expires
            or target.issuer_spki_digest == authorizer_id):
        _fail()
    target.live()
    budget.check()
    return target


def _admit(original, public, request_bytes, issuer_bytes, budget):
    if not original.endswith(b"\n"):
        _fail()
    envelope = _decode(original[:-1], MAX_BYTES - 1, budget)
    shared._object(envelope, {"apiVersion", "delegation", "signatureBase64url"})
    if envelope["apiVersion"] != SCHEMA or type(envelope["delegation"]) is not dict:
        _fail()
    signature = assignment._base64(envelope["signatureBase64url"], 64)
    value = envelope["delegation"]
    message = SIGNATURE_DOMAIN + packets._canonical(value, MAX_PAYLOAD_BYTES, budget)
    budget.charge(input_bytes=len(message), hashes=1)
    public.verify(signature, message)
    budget.check()
    target = _payload(value, public, request_bytes, issuer_bytes, budget)
    digest = packets._digest(original, budget)
    target.live()
    return _DelegationMaterial(digest, value["authorizerKeyId"], value["delegationId"],
        value["releaseRecordSha256"], value["policyHash"], value["configurationSha256"],
        value["runtimeCaCertificateSha256"], value["runtimeCaSpkiSha256"],
        value["ingressLeafCertificateSha256"], value["clientTrustBundleSha256"],
        value["callerPrincipalId"], value["callerIssuerCertificateSha256"],
        value["callerIssuerSpkiSha256"], value["callerCertificateSha256"], value["callerSpkiSha256"],
        value["ingressHost"], value["serverInstanceId"], value["proxyEndpoint"],
        value["clientChallengeBase64url"], value["targetPrincipalId"], value["targetNonce"],
        value["targetRequestSha256"], value["targetCsrSha256"], value["targetSpkiSha256"],
        target.requested_sans, value["targetIssuerCertificateDerSha256"],
        value["targetIssuerSpkiSha256"], target.created_at_epoch_ms,
        target.expires_at_epoch_ms, value["notBeforeUnixSeconds"], value["expiresAtUnixSeconds"],
        budget.window, budget.bound, target.live)


def _verify_on_work(*, delegation_bytes, authorizer_public_key_bytes,
        expected_authorizer_pem_sha256, target_request_bytes, target_issuer_certificate_bytes,
        work, live_window, transport_deadline_ns, _current=None, _additional_original_bytes=0):
    """Verify exact originals with inherited work; returned facts are not admission."""
    try:
        _preflight(((delegation_bytes, MAX_BYTES), (authorizer_public_key_bytes, MAX_KEY_BYTES),
            (target_request_bytes, MAX_REQUEST_BYTES), (target_issuer_certificate_bytes, MAX_ISSUER_BYTES)),
            _additional_original_bytes, work)
        budget = assignment._Lifetime(work, live_window, transport_deadline_ns, _current)
        public = assignment._public_key(authorizer_public_key_bytes, expected_authorizer_pem_sha256, budget)
        return _admit(delegation_bytes, public, target_request_bytes, target_issuer_certificate_bytes, budget)
    except NativeEnrollmentBootstrapDelegationError:
        raise
    except Exception:
        raise NativeEnrollmentBootstrapDelegationError(
            "native enrollment bootstrap delegation verification failed") from None


def _produce_on_work(*, payload_bytes, authorizer_private_key_bytes, authorizer_public_key_bytes,
        expected_authorizer_pem_sha256, target_request_bytes, target_issuer_certificate_bytes,
        work, live_window, transport_deadline_ns, _current=None, _additional_original_bytes=0):
    """Explicit dedicated-authorizer operation over exact already-selected scope.

    No target digest, identity or expiry is filled in or silently changed. The
    canonical unencrypted PKCS8 original is supplied directly; no path lookup,
    key generation, private output or erased-memory guarantee is provided.
    """
    try:
        _preflight(((payload_bytes, MAX_PAYLOAD_BYTES), (authorizer_private_key_bytes, MAX_KEY_BYTES),
            (authorizer_public_key_bytes, MAX_KEY_BYTES), (target_request_bytes, MAX_REQUEST_BYTES),
            (target_issuer_certificate_bytes, MAX_ISSUER_BYTES)), _additional_original_bytes,
            work, producing=True)
        budget = assignment._Lifetime(work, live_window, transport_deadline_ns, _current)
        public = assignment._public_key(authorizer_public_key_bytes, expected_authorizer_pem_sha256, budget)
        payload = _decode(payload_bytes, MAX_PAYLOAD_BYTES, budget)
        target = _payload(payload, public, target_request_bytes, target_issuer_certificate_bytes, budget)
        budget.charge(input_bytes=len(authorizer_private_key_bytes))
        private = serialization.load_pem_private_key(authorizer_private_key_bytes, password=None)
        budget.check()
        if (not isinstance(private, ed25519.Ed25519PrivateKey)
                or private.private_bytes(serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
                    != authorizer_private_key_bytes
                or shared._spki(private.public_key(), budget) != shared._spki(public, budget)):
            _fail()
        target.live()
        message = SIGNATURE_DOMAIN + payload_bytes
        budget.charge(input_bytes=len(message), hashes=1)
        signature = private.sign(message)
        budget.check()
        target.live()
        original = packets._canonical({"apiVersion": SCHEMA, "delegation": payload,
            "signatureBase64url": base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")},
            MAX_BYTES - 1, budget) + b"\n"
        admitted = _admit(original, public, target_request_bytes, target_issuer_certificate_bytes, budget)
        admitted.live()
        budget.check()
        return original
    except NativeEnrollmentBootstrapDelegationError:
        raise
    except Exception:
        raise NativeEnrollmentBootstrapDelegationError(
            "native enrollment bootstrap delegation production failed") from None
