"""Offline authority for the complete, immutable native workload trust set.

The supplied private key authorizes exact independently selected originals; no
key generation, ambient policy-key loading, publication or runtime admission is
performed here. The native consumer separately checks actual generated keys,
the attested policy owner, retained TLS roots and the original guest lifetime.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from catchplate import authority_contract
from catchplate import policy_bundle
from catchplate import workload_identity_issuer_bootstrap as shared
from catchplate_agent_trust import _workload_signed_packet as packets
from catchplate_agent_trust import workload_identity_originals as certificates


SCHEMA = "catchplate.signedNativeWorkloadIdentityTrustAuthorization/v1"
PAYLOAD_SCHEMA = "catchplate.nativeWorkloadIdentityTrustAuthorization/v1"
PROFILE = "immutable-native-framed-der-startup-v1"
CONFIGURATION_SCHEMA = "catchplate.nativeStartupConfiguration/v22"
MAX_BYTES = 128 * 1024
MAX_CONFIGURATION_BYTES = 16 * 1024 * 1024
MAX_LAUNCH_BYTES = MAX_KEY_BYTES = 16 * 1024
MAX_POLICY_BYTES = 8 * 1024 * 1024
MAX_ROOT_BYTES = MAX_PRINCIPALS_BYTES = 64 * 1024
MAX_ROOT_TOTAL_BYTES = 1024 * 1024
MAX_LIFETIME_NS = 86_400_000_000_000
_CONFIGURATION_FIELDS = frozenset({
    "apiVersion", "gate", "native", "shadow", "responseObservationV2", "policy",
    "enrollmentAuthorizer", "enrollmentSetupAuthorizer", "enrollmentProxyEndpoint",
    "credentialCurrentness", "secretBroker", "measuredAudit", "encryptedServiceTokens",
    "measuredRefresh", "guestInspector", "measuredSuccession", "guestCohort",
    "measuredCleanup", "guestRoleKeyProvisioner", "measuredPendingRetirement",
    "gateCgroup", "measuredCaptureRetirement", "measuredCanaryDelivery", "workloadTrustAuthorizer",
})
_LAUNCH_FIELDS = frozenset({
    "apiVersion", "releaseRecordSha256", "configurationSha256", "deadlineBoottimeNs",
    "caNotBeforeUnixSeconds", "caNotAfterUnixSeconds", "ingressNotBeforeUnixSeconds",
    "ingressNotAfterUnixSeconds", "ingressNonceBase64url", "proofNonceBase64url",
})
_NATIVE_FIELDS = frozenset({
    "ingressHost", "ingressClientRootsDerBase64url", "controlPlaneResponsePublicKeyPem",
    "controlPlaneResponseKeyId", "attemptLedgerDirectory", "relayAssignments",
    "listenerPort", "expectedPolicySigningKeyId", "runtime",
})
_ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


class NativeWorkloadTrustAuthorizationError(ValueError):
    pass


def _require(value):
    if not value:
        raise NativeWorkloadTrustAuthorizationError("native workload trust authorization refused")


def _text(value, maximum):
    _require(type(value) is str and 1 <= len(value) <= maximum
        and all(32 <= ord(character) <= 126 for character in value))
    return value


def _digest(raw, budget):
    return packets._digest(raw, budget)


def _document(raw, maximum, budget, *, policy=False):
    shared._raw(raw, maximum)
    if policy:
        # Use the actual policy parser, including finite binary64 v2 values.
        # The integer-only workload packet parser is not a policy substitute.
        budget.charge(input_bytes=len(raw))
        value = policy_bundle.strict_json_loads(raw)
    else:
        packets._preflight_json(raw, budget)
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=packets._unique_object,
            parse_int=packets._integer, parse_float=packets._reject_number,
            parse_constant=packets._reject_number)
    _require(type(value) is dict)
    pending, nodes = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        _require(nodes <= 100_000 and depth <= 64)
        if nodes % 1024 == 0:
            budget.check()
        if type(item) is dict:
            pending.extend((child, depth + 1) for pair in item.items() for child in pair)
        elif type(item) is list:
            pending.extend((child, depth + 1) for child in item)
        elif type(item) is str:
            item.encode("utf-8")  # No lone surrogate in either original.
    budget.charge(json_nodes=nodes)
    # Configuration/launch/policy pins commit to their exact original bytes,
    # not a rewritten JSON spelling. Only the new signed grant is canonical.
    return value


def _key(raw, budget):
    shared._raw(raw, MAX_KEY_BYTES)
    budget.charge(input_bytes=len(raw))
    key = serialization.load_pem_public_key(raw)
    _require(isinstance(key, ed25519.Ed25519PublicKey))
    _require(key.public_bytes(serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo) == raw)
    spki = shared._spki(key, budget)
    _require(len(spki) == 44 and spki.startswith(_ED25519_SPKI_PREFIX))
    return key, spki, _digest(spki, budget)


def _configured_key(value, budget, *, api=None):
    fields = {"publicKeyPem", "publicKeyPemSha256"}
    if api is not None:
        fields.add("apiVersion")
    shared._object(value, fields)
    if api is not None:
        _require(value["apiVersion"] == api)
    raw = value["publicKeyPem"].encode("ascii")
    _require(_digest(raw, budget) == shared._digest(value["publicKeyPemSha256"]))
    return _key(raw, budget)


def _base64(value, maximum):
    _require(type(value) is str and 1 <= len(value) <= (maximum * 4 + 2) // 3)
    raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    _require(1 <= len(raw) <= maximum
        and base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") == value)
    return raw


def _epoch_ns(value):
    # Exact integral X.509 second precision, without floating timestamp rounding.
    delta = value - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (delta.days * 86_400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1000


def _roots(encoded, authorizer_spki, issued, expires, budget):
    _require(type(encoded) is list and 1 <= len(encoded) <= 32)
    seen, issuers, inventory, total = set(), set(), [], 0
    framed = bytearray(b"catchplate/mutual-tls-client-trust/v1\0")
    framed.extend(len(encoded).to_bytes(4, "big"))
    for spelling in encoded:
        der = _base64(spelling, MAX_ROOT_BYTES)
        total += len(der)
        _require(total <= MAX_ROOT_TOTAL_BYTES and der not in seen)
        seen.add(der)
        # Preserve the original DER. This derived PEM wrapper only adapts the
        # existing restricted CA/key/extension verifier; no PEM byte cap is
        # substituted for the native 64KiB DER bound.
        pem = b"-----BEGIN CERTIFICATE-----\n" + base64.b64encode(der) + b"\n-----END CERTIFICATE-----\n"
        original = certificates._issuer(pem, budget)
        _require(original.der == der and original.spki_der != authorizer_spki
            and _epoch_ns(original.certificate.not_valid_before_utc) <= issued
            and expires <= _epoch_ns(original.certificate.not_valid_after_utc))
        issuer = _digest(original.spki_der, budget)
        issuers.add(issuer)
        inventory.append({"certificateDerSha256": _digest(der, budget), "spkiSha256": issuer})
        framed.extend(len(der).to_bytes(8, "big"))
        framed.extend(der)
    return inventory, issuers, _digest(bytes(framed), budget)


def _principals(policy, issuers, budget):
    source = policy.get("principals")
    _require(type(source) is list and bool(source))
    result, ids = [], set()
    for item in source:
        _require(type(item) is dict)
        principal = item.get("id")
        _require(type(principal) is str and principal not in ids)
        ids.add(principal)
        if "mtls" in item:
            _require(type(item["mtls"]) is dict)
            for name in ("certificateSha256", "spkiSha256", "issuerSpkiSha256"):
                if name in item["mtls"]:
                    shared._digest(item["mtls"][name])
        # The genuine policy selector validator provides the same normalized
        # selectors as the compiler; do not sign a caller's selected subset.
        mtls = policy_bundle._validate_mtls_identity_policy(principal, item.get("mtls"))
        if mtls is None:
            continue
        _text(principal, 512)
        issuer = mtls.get("issuerSpkiSha256")
        _require(issuer is not None and len(issuer) == 1 and issuer[0] in issuers)
        entry = {"verifiedByTrustedIngress": True, "issuerSpkiSha256": issuer[0]}
        for name, maximum in (("sanSpiffeIds", 2048), ("sanDnsNames", 253), ("sanUris", 2048)):
            if mtls.get(name):
                entry[name] = sorted(_text(text, maximum) for text in mtls[name])
        for name in ("certificateSha256", "spkiSha256"):
            if name in mtls:
                entry[name] = shared._digest(mtls[name][0])
        _require(len(entry) > 2)
        result.append({"principalId": principal, "mtls": entry})
        _require(len(result) <= 64)
    _require(bool(result))
    result.sort(key=lambda value: value["principalId"])
    packets._canonical({"schema": "catchplate.workloadIdentityTrustPrincipals/v1",
        "principals": result}, MAX_PRINCIPALS_BYTES, budget)
    return result


def _derive(configuration_bytes, launch_bytes, policy_bytes, policy_public_key_bytes, *,
        expected_configuration_sha256, expected_launch_sha256,
        expected_policy_public_key_sha256, issued_at_epoch_ns, expires_at_epoch_ns, budget):
    configuration_pin = shared._digest(expected_configuration_sha256)
    launch_pin = shared._digest(expected_launch_sha256)
    _require(_digest(configuration_bytes, budget) == configuration_pin
        and _digest(launch_bytes, budget) == launch_pin
        and _digest(policy_public_key_bytes, budget) == shared._digest(expected_policy_public_key_sha256))
    configuration = _document(configuration_bytes, MAX_CONFIGURATION_BYTES, budget)
    shared._object(configuration, _CONFIGURATION_FIELDS)
    _require(configuration["apiVersion"] == CONFIGURATION_SCHEMA)
    launch = _document(launch_bytes, MAX_LAUNCH_BYTES, budget)
    shared._object(launch, _LAUNCH_FIELDS)
    _require(launch["apiVersion"] == "catchplate.nativeStartupLaunch/v1"
        and launch["configurationSha256"] == configuration_pin)
    deadline = shared._integer(launch["deadlineBoottimeNs"], minimum=1)
    for name in ("ingressNonceBase64url", "proofNonceBase64url"):
        nonce = _base64(launch[name], 32)
        _require(len(nonce) == 32 and any(nonce))
    issued = shared._integer(issued_at_epoch_ns, minimum=1)
    expires = shared._integer(expires_at_epoch_ns, minimum=issued + 1)
    _require(expires - issued <= MAX_LIFETIME_NS)
    budget.interval(issued, expires)
    for name in ("ca", "ingress"):
        before, after = (launch[name + suffix] for suffix in ("NotBeforeUnixSeconds", "NotAfterUnixSeconds"))
        _require(type(before) is int and type(after) is int and -(1 << 63) <= before < after <= (1 << 63) - 1
            and before * 1_000_000_000 <= issued < expires <= after * 1_000_000_000)
    native = shared._object(configuration["native"], _NATIVE_FIELDS)
    authorizer, authorizer_spki, authorizer_id = _configured_key(configuration["workloadTrustAuthorizer"], budget)
    policy_key, _, policy_key_id = _key(policy_public_key_bytes, budget)
    _require(policy_key_id == shared._digest(native["expectedPolicySigningKeyId"]))
    excluded = [policy_key_id]
    _, _, response_id = _key(native["controlPlaneResponsePublicKeyPem"].encode("ascii"), budget)
    _require(response_id == shared._digest(native["controlPlaneResponseKeyId"]))
    excluded.append(response_id)
    for field, api in (("enrollmentAuthorizer", "catchplate.nativeEnrollmentAuthorizer/v1"),
            ("enrollmentSetupAuthorizer", "catchplate.nativeEnrollmentSetupAuthorizer/v1")):
        excluded.append(_configured_key(configuration[field], budget, api=api)[2])
    _require(authorizer_id not in excluded)
    roots, issuers, bundle = _roots(native["ingressClientRootsDerBase64url"], authorizer_spki,
        issued, expires, budget)
    policy_pin = shared._object(configuration["policy"], {"path", "sha256"})
    _require(_digest(policy_bytes, budget) == shared._digest(policy_pin["sha256"]))
    policy = _document(policy_bytes, MAX_POLICY_BYTES, budget, policy=True)
    _require(policy.get("apiVersion") in {"catchplate.policy/v1", "catchplate.policy/v2"}
        and policy.get("kind") == "PolicyBundle")
    metadata = policy.get("metadata")
    _require(type(metadata) is dict and metadata.get("signingKeyId") == policy_key_id)
    encoded = metadata.get("signature")
    _require(type(encoded) is str and encoded.startswith("ed25519:"))
    signature = _base64(encoded[8:], 64)
    _require(len(signature) == 64)
    message = policy_bundle.policy_signature_bytes(policy)
    budget.charge(hashes=1, input_bytes=len(message))
    policy_key.verify(signature, message)
    policy_digest = _digest(message, budget)
    gate = configuration["gate"]
    checkpoint = shared._object(gate["policyHighWater"],
        {"apiVersion", "policyId", "sequence", "rollbackEpoch", "policyHash"})
    sequence = shared._integer(metadata.get("sequence"), minimum=1)
    rollback = shared._integer(metadata.get("rollbackEpoch"), minimum=1)
    _require(checkpoint["apiVersion"] == "catchplate.policyHighWater/v1"
        and checkpoint["policyId"] == metadata.get("id")
        and checkpoint["policyHash"] == policy_digest
        and type(checkpoint["sequence"]) is int and checkpoint["sequence"] == sequence
        and type(checkpoint["rollbackEpoch"]) is int and checkpoint["rollbackEpoch"] == rollback)
    currentness = shared._object(configuration["credentialCurrentness"], {"profile", "deploymentId"})
    _require(currentness["profile"] == "measured-holder-barrier-v1")
    deployment = shared._identifier(currentness["deploymentId"])
    _require(configuration["measuredCanaryDelivery"]["deploymentId"] == deployment
        and configuration["measuredSuccession"]["deploymentId"] == deployment)
    payload = {
        "schema": PAYLOAD_SCHEMA, "sourceRevision": authority_contract.SOURCE_REVISION,
        "purpose": "native-workload-identity-ingress-trust", "profile": PROFILE,
        "authorizerSpkiSha256": authorizer_id, "deploymentId": deployment,
        "instanceId": _text(gate["instanceId"], 1024),
        "configurationSha256": configuration_pin, "launchSha256": launch_pin,
        "releaseRecordSha256": shared._digest(launch["releaseRecordSha256"]),
        "policyHash": policy_digest, "policySequence": sequence, "rollbackEpoch": rollback,
        "deadlineBoottimeNs": deadline, "clientTrustProfile": "native-framed-der-v1",
        "clientTrustBundleSha256": bundle, "issuers": roots,
        "principals": _principals(policy, issuers, budget),
        "issuedAtEpochNs": issued, "expiresAtEpochNs": expires,
    }
    budget.check()
    return payload, authorizer


def produce_on_work(*, configuration_bytes, launch_bytes, policy_bytes, policy_public_key_bytes,
        expected_configuration_sha256, expected_launch_sha256, expected_policy_public_key_sha256,
        authorizer_private_key, issued_at_epoch_ns, expires_at_epoch_ns,
        work, live_window, transport_deadline_ns, _current=None):
    """Sign once with an independently supplied matching key; return no-LF bytes.

    There is no caller-authored payload/principal/root summary. Full ordinary
    configuration semantics, live native key separation, rollback witnesses and
    guest BOOTTIME admission remain required at the real startup consumer.
    """
    try:
        budget = shared._Budget(work, live_window, transport_deadline_ns, _current)
        for raw, maximum in ((configuration_bytes, MAX_CONFIGURATION_BYTES),
                (launch_bytes, MAX_LAUNCH_BYTES), (policy_bytes, MAX_POLICY_BYTES),
                (policy_public_key_bytes, MAX_KEY_BYTES)):
            shared._raw(raw, maximum)
        payload, public = _derive(configuration_bytes, launch_bytes, policy_bytes, policy_public_key_bytes,
            expected_configuration_sha256=expected_configuration_sha256,
            expected_launch_sha256=expected_launch_sha256,
            expected_policy_public_key_sha256=expected_policy_public_key_sha256,
            issued_at_epoch_ns=issued_at_epoch_ns, expires_at_epoch_ns=expires_at_epoch_ns, budget=budget)
        original = packets._canonical(payload, MAX_BYTES, budget)
        result = shared._produce(original, SCHEMA, PAYLOAD_SCHEMA, authorizer_private_key,
            public, MAX_BYTES, budget)
        _require(shared._signed(result, SCHEMA, PAYLOAD_SCHEMA, public, MAX_BYTES, budget) == payload)
        budget.check()
        return result
    except Exception:
        # Public configuration may still contain bearer/capability fields.
        # Neither originals, key material nor crypto/parser detail escapes.
        raise NativeWorkloadTrustAuthorizationError("native workload trust authorization refused") from None
