"""Independent public authority for one immutable workload ingress trust anchor.

This original-only profile authorizes publication and explicit startup/restart,
not certificate issuance, hot reload, key custody, channel acceptance or rotation.
The verifier's expected scope must come from independent operator/startup inputs;
in particular a record cannot supply its own trusted authorizer or policy hash.
The Rust consumer additionally joins the full genuine signed-policy inventory
and excludes its actual policy signing key. A publisher does not make that claim.

Authorizations last at most 24 hours, entirely within the original CA interval.
The caller's shorter processing window is preserved, not a new service lifetime.
There is no sequence journal or independent latest-state/rollback witness here.
Replaying an otherwise valid original before expiry is not prevented by this
signature alone. Single-issuer cutover is not overlapping-issuer migration.
"""
from __future__ import annotations

from dataclasses import dataclass
import re

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from serverware import workload_identity_issuer_bootstrap as shared
from serverware_agent_trust import _workload_signed_packet as packets
from serverware_agent_trust import workload_identity_originals as originals
from serverware_agent_trust.workload_transport import validate_mtls_identity


SCHEMA = "serverware.signedWorkloadIdentityTrustAuthorization/v1"
PAYLOAD_SCHEMA = "serverware.workloadIdentityTrustAuthorization/v1"
PRINCIPALS_SCHEMA = "serverware.workloadIdentityTrustPrincipals/v1"
SCOPE_SCHEMA = "serverware.workloadIdentityTrustStartupScope/v1"
PROFILE = "immutable-single-issuer-startup-v1"
MAX_BYTES = 128 * 1024
MAX_BUNDLE_BYTES = MAX_ISSUER_BYTES = 64 * 1024
MAX_KEY_BYTES = 16 * 1024
MAX_PRINCIPALS_BYTES = 64 * 1024
MAX_ORIGINAL_BYTES = 64 * 1024 * 1024
MAX_LIFETIME_NS = 24 * 60 * 60 * 1_000_000_000
clock = shared.clock
_Budget = shared._Budget
_FIELDS = frozenset({
    "schema", "sourceRevision", "purpose", "trustMode", "profile", "authorizerSpkiSha256",
    "deploymentId", "configurationDigest", "runtimeBinarySha256", "serverCertificateSpkiSha256",
    "policyHash", "bundle", "issuer", "principals", "issuedAtEpochNs", "expiresAtEpochNs",
})
_SAN_FIELDS = ("sanDnsNames", "sanUris", "sanSpiffeIds")


class WorkloadIdentityTrustAuthorizationError(ValueError):
    pass


def _fail():
    raise WorkloadIdentityTrustAuthorizationError("workload public trust authorization is invalid")


def _construction_on_work(work):
    """Existing 30-second, zero-skew processing profile on the supplied ledger."""
    return shared._construction_on_work(work)


@dataclass(frozen=True, slots=True, repr=False)
class _TrustMaterial:
    authorization_bytes: bytes
    authorization_digest: str
    authorizer_public_key_bytes: bytes
    authorizer_spki_digest: str
    bundle_bytes: bytes
    bundle_digest: str
    issuer_certificate_bytes: bytes
    issuer_der_digest: str
    issuer_spki_digest: str
    deployment_id: str
    configuration_digest: str
    runtime_binary_sha256: str
    server_certificate_spki_sha256: str
    policy_hash: str
    principals_bytes: bytes
    valid_from_epoch_ns: int
    valid_until_epoch_ns: int
    window: tuple
    deadline_ns: int
    live: object


def _ascii_text(value, maximum):
    if (type(value) is not str or not 1 <= len(value) <= maximum
            or any(not 32 <= ord(character) <= 126 for character in value)):
        _fail()
    return value


def _deployment(value):
    if (type(value) is not str
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value) is None):
        _fail()
    return value


def _public_key(raw, budget):
    shared._raw(raw, MAX_KEY_BYTES)
    budget.charge(input_bytes=len(raw))
    key = serialization.load_pem_public_key(raw)
    budget.check()
    if (not isinstance(key, ed25519.Ed25519PublicKey)
            or key.public_bytes(serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo) != raw):
        _fail()
    return key


def _principals(value, issuer_spki, budget):
    if type(value) is not list or not 1 <= len(value) <= 64:
        _fail()
    previous = None
    for principal in value:
        budget.check()
        shared._object(principal, {"principalId", "mtls"})
        identifier = _ascii_text(principal["principalId"], 512)
        if previous is not None and identifier <= previous:
            _fail()
        previous = identifier
        mtls = principal["mtls"]
        if type(mtls) is not dict:
            _fail()
        # Reuse the actual signed-policy selector spelling, then close this
        # profile to sorted, ASCII-only arrays for identical cross-language
        # canonical encoding. Omitted optional members never become null.
        normalized = validate_mtls_identity(mtls)
        if (mtls != normalized or mtls.get("issuerSpkiSha256") != issuer_spki
                or mtls.get("verifiedByTrustedIngress") is not True):
            _fail()
        for name in _SAN_FIELDS:
            if name not in mtls:
                continue
            entries = mtls[name]
            if (type(entries) is not list or not 1 <= len(entries) <= 32
                    or entries != sorted(set(entries))):
                _fail()
            for entry in entries:
                _ascii_text(entry, 253 if name == "sanDnsNames" else 2048)
        for name in ("certificateSha256", "spkiSha256", "issuerSpkiSha256"):
            if name in mtls:
                shared._digest(mtls[name])
    return packets._canonical({"schema": PRINCIPALS_SCHEMA, "principals": value},
        MAX_PRINCIPALS_BYTES, budget)


def _scope(*, deployment_id, runtime_binary_sha256, server_certificate_spki_sha256,
        policy_hash, bundle_digest, budget):
    scope = {"schema": SCOPE_SCHEMA, "profile": PROFILE,
        "deploymentId": _deployment(deployment_id),
        "runtimeBinarySha256": shared._digest(runtime_binary_sha256),
        "policyHash": shared._digest(policy_hash),
        "serverCertificateSpkiSha256": shared._digest(server_certificate_spki_sha256),
        "clientTrustBundleSha256": shared._digest(bundle_digest)}
    return packets._digest(packets._canonical(scope, 4096, budget), budget)


def _preflight(authorization_bytes, bundle_bytes, issuer_certificate_bytes,
        authorizer_public_key_bytes, expected_principals_bytes, additional, work):
    clock.evidence.capture._SharedLedger(work)
    shared._integer(additional, MAX_ORIGINAL_BYTES)
    total = 0
    for original, maximum in ((authorization_bytes, MAX_BYTES),
            (bundle_bytes, MAX_BUNDLE_BYTES), (issuer_certificate_bytes, MAX_ISSUER_BYTES),
            (authorizer_public_key_bytes, MAX_KEY_BYTES),
            (expected_principals_bytes, MAX_PRINCIPALS_BYTES)):
        shared._raw(original, maximum)
        total += len(original)
    if (additional + 8 * total + 128 * 1024 > min(MAX_ORIGINAL_BYTES,
            work.limits.max_input_bytes - work.metrics.input_bytes)):
        _fail()


def _verify_on_work(*, authorization_bytes, bundle_bytes, issuer_certificate_bytes,
        authorizer_public_key_bytes, expected_deployment_id, expected_runtime_binary_sha256,
        expected_server_certificate_spki_sha256, expected_policy_hash, expected_principals_bytes,
        work, live_window, transport_deadline_ns, _current=None, _additional_original_bytes=0):
    """Admit original public bytes; no previously successful material is accepted."""
    try:
        _preflight(authorization_bytes, bundle_bytes, issuer_certificate_bytes,
            authorizer_public_key_bytes, expected_principals_bytes, _additional_original_bytes, work)
        budget = _Budget(work, live_window, transport_deadline_ns, _current)
        public = _public_key(authorizer_public_key_bytes, budget)
        payload = shared._signed(authorization_bytes, SCHEMA, PAYLOAD_SCHEMA,
            public, MAX_BYTES, budget)
        shared._object(payload, _FIELDS)
        if (payload["purpose"] != "workload-identity-ingress-trust"
                or payload["trustMode"] != "trusted-host-local" or payload["profile"] != PROFILE):
            _fail()
        issued = shared._integer(payload["issuedAtEpochNs"], minimum=1)
        expires = shared._integer(payload["expiresAtEpochNs"], minimum=issued + 1)
        if expires - issued > MAX_LIFETIME_NS:
            _fail()
        budget.interval(issued, expires)
        # The exact same single canonical PEM is both the published bundle and
        # independently selected issuing CA. No extra certificate or whitespace
        # can create an implicit overlapping trust set.
        if bundle_bytes != issuer_certificate_bytes:
            _fail()
        issuer = originals._issuer(issuer_certificate_bytes, budget)
        budget.charge(input_bytes=len(issuer_certificate_bytes), hashes=2)
        canonical_pem = issuer.certificate.public_bytes(serialization.Encoding.PEM)
        if canonical_pem != bundle_bytes:
            _fail()
        ca_from = int(issuer.certificate.not_valid_before_utc.timestamp()) * 1_000_000_000
        ca_until = int(issuer.certificate.not_valid_after_utc.timestamp()) * 1_000_000_000
        if not ca_from <= issued < expires <= ca_until:
            _fail()
        issuer_der_digest = packets._digest(issuer.der, budget)
        issuer_spki_digest = packets._digest(issuer.spki_der, budget)
        authorizer_spki = shared._spki(public, budget)
        if issuer.spki_der == authorizer_spki:
            _fail()
        authorizer_digest = packets._digest(authorizer_spki, budget)
        bundle_digest = packets._digest(bundle_bytes, budget)
        bundle = shared._object(payload["bundle"], {"byteCount", "bytesDigest"})
        issuer_pins = shared._object(payload["issuer"], {"certificateDerSha256", "spkiSha256"})
        if (type(bundle["byteCount"]) is not int or bundle["byteCount"] != len(bundle_bytes)
                or bundle["bytesDigest"] != bundle_digest
                or issuer_pins["certificateDerSha256"] != issuer_der_digest
                or issuer_pins["spkiSha256"] != issuer_spki_digest
                or payload["authorizerSpkiSha256"] != authorizer_digest):
            _fail()
        expected = {"deploymentId": _deployment(expected_deployment_id),
            "runtimeBinarySha256": shared._digest(expected_runtime_binary_sha256),
            "serverCertificateSpkiSha256": shared._digest(expected_server_certificate_spki_sha256),
            "policyHash": shared._digest(expected_policy_hash)}
        if any(type(payload[name]) is not str or payload[name] != value
                for name, value in expected.items()):
            _fail()
        configuration = _scope(deployment_id=expected_deployment_id,
            runtime_binary_sha256=expected_runtime_binary_sha256,
            server_certificate_spki_sha256=expected_server_certificate_spki_sha256,
            policy_hash=expected_policy_hash, bundle_digest=bundle_digest, budget=budget)
        if payload["configurationDigest"] != configuration:
            _fail()
        principal_bytes = _principals(payload["principals"], issuer_spki_digest, budget)
        expected_principals = shared._decode(expected_principals_bytes, MAX_PRINCIPALS_BYTES, budget)
        shared._object(expected_principals, {"schema", "principals"})
        if (expected_principals["schema"] != PRINCIPALS_SCHEMA
                or _principals(expected_principals["principals"], issuer_spki_digest, budget)
                    != expected_principals_bytes
                or principal_bytes != expected_principals_bytes):
            _fail()
        budget.check()
        return _TrustMaterial(authorization_bytes, packets._digest(authorization_bytes, budget),
            authorizer_public_key_bytes, authorizer_digest, bundle_bytes, bundle_digest,
            issuer_certificate_bytes, issuer_der_digest, issuer_spki_digest,
            expected_deployment_id, configuration, expected_runtime_binary_sha256,
            expected_server_certificate_spki_sha256, expected_policy_hash, principal_bytes,
            issued, expires, budget.window, budget.bound, budget.current)
    except WorkloadIdentityTrustAuthorizationError:
        raise
    except Exception:
        raise WorkloadIdentityTrustAuthorizationError("workload public trust originals were refused") from None


def _produce_on_work(*, payload_bytes, authorizer_private_key, authorizer_public_key_bytes,
        bundle_bytes, issuer_certificate_bytes, expected_deployment_id, expected_runtime_binary_sha256,
        expected_server_certificate_spki_sha256, expected_policy_hash, expected_principals_bytes,
        work, live_window, transport_deadline_ns, _current=None, _additional_original_bytes=0):
    """Sign the closed original payload, then genuinely re-admit the resulting original."""
    try:
        _preflight(payload_bytes, bundle_bytes, issuer_certificate_bytes,
            authorizer_public_key_bytes, expected_principals_bytes, _additional_original_bytes, work)
        budget = _Budget(work, live_window, transport_deadline_ns, _current)
        public = _public_key(authorizer_public_key_bytes, budget)
        original = shared._produce(payload_bytes, SCHEMA, PAYLOAD_SCHEMA,
            authorizer_private_key, public, MAX_BYTES, budget)
        _verify_on_work(authorization_bytes=original, bundle_bytes=bundle_bytes,
            issuer_certificate_bytes=issuer_certificate_bytes,
            authorizer_public_key_bytes=authorizer_public_key_bytes,
            expected_deployment_id=expected_deployment_id,
            expected_runtime_binary_sha256=expected_runtime_binary_sha256,
            expected_server_certificate_spki_sha256=expected_server_certificate_spki_sha256,
            expected_policy_hash=expected_policy_hash, expected_principals_bytes=expected_principals_bytes,
            work=work, live_window=budget.window, transport_deadline_ns=budget.bound,
            _current=budget.current, _additional_original_bytes=_additional_original_bytes)
        budget.check()
        return original
    except WorkloadIdentityTrustAuthorizationError:
        raise
    except Exception:
        raise WorkloadIdentityTrustAuthorizationError("workload public trust authorization production failed") from None
