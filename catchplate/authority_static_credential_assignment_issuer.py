"""Purpose-fixed offline issuance from independently approved public originals.

The startup quote authenticates retained role-4 material, not a new challenge,
current serving readiness or permission to mutate a credential. The original
input hash/root/key selection remain the independent authority's responsibility.
No key loading, collection, clock generation, provisioning or network belongs
here. Native action verification remains mandatory after this assignment.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import base64
import hashlib
import json

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from scripts import verify_nitro_tee as nitro
from catchplate import authority_contract as contract
from catchplate import authority_credential_currentness as current
from catchplate import authority_credential_currentness_policy as current_policy
from catchplate import authority_policy_canary_policy as configuration
from catchplate import authority_request_commitment as commitment
from catchplate import authority_static_credential_assignment as assignment
from catchplate import authority_static_credential_create as creation
from catchplate import authority_static_credential_custody as custody
from catchplate import authority_static_credential_rotate as rotation

API = "catchplate.staticCredentialAssignmentAuthorityInput/v1"
SIGNED_CONFIGURATION = "catchplate.signedPolicyAuthorityServiceConfiguration/v6"
IDENTITY_API = "catchplate.nativeResponseProofPublicIdentity/v1"
MAX_IDENTITY = 64 * 1024
MAX_LAUNCH = 16 * 1024
MAX_INPUT = 2 * contract.MAX_REQUEST_BYTES + 2 * (MAX_IDENTITY + MAX_LAUNCH) + 16384
FIELDS = frozenset({"apiVersion", "configurationOriginal", "configurationRoot",
    "nativeIdentityOriginal", "nativeLaunchOriginal", "expectedModuleId",
    "issuedAtEpochNs", "expiresAtEpochNs"})
IDENTITY_FIELDS = frozenset({"apiVersion", "purpose", "evidenceScope", "okForAction",
    "bootId", "keyId", "publicKeyPem", "controlPlaneResponseSigningKeyId", "scope",
    "caCertificateDerBase64url", "nativeKeyEvidence", "quoteNonceBase64url", "quoteUserDataBase64url"})
SCOPE_FIELDS = ("releaseRecordSha256", "policyHash", "configurationSha256",
    "caCertificateSha256", "caPublicKeySpkiSha256")
LAUNCH_FIELDS = frozenset({"apiVersion", "releaseRecordSha256", "configurationSha256",
    "deadlineBoottimeNs", "caNotBeforeUnixSeconds", "caNotAfterUnixSeconds",
    "ingressNotBeforeUnixSeconds", "ingressNotAfterUnixSeconds",
    "ingressNonceBase64url", "proofNonceBase64url"})
canonical, require, sha256, digest = creation.canonical, creation.require, creation.sha256, creation.digest


def document(raw, maximum, *, exact=True):
    """Bounded duplicate-refusing JSON; original strings are never rewritten."""
    require(type(raw) is bytes and 0 < len(raw) <= maximum)
    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result)
            result[key] = value
        return result
    value = json.loads(raw.decode("ascii"), object_pairs_hook=pairs,
        parse_constant=lambda _: require(False))
    require(type(value) is dict)
    pending, count = [(value, 0)], 0
    while pending:
        item, depth = pending.pop(); count += 1
        require(count <= 65536 and depth <= 32)
        if type(item) is dict:
            pending.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            pending.extend((child, depth + 1) for child in item)
        else:
            require(item is None or type(item) in {str, int, float, bool})
    normalized = canonical(value)  # Also rejects nonfinite numeric overflow.
    require(not exact or normalized == raw)
    return value


def _original(value, maximum, *, exact=True):
    require(type(value) is str and value.isascii())
    return document(value.encode("ascii"), maximum, exact=exact)


def _spki(key):
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _configuration(value):
    selected = value["configurationRoot"]
    require(type(selected) is dict and set(selected) == assignment.AUTHORIZER_FIELDS
        and type(selected["publicKeyPem"]) is str and 0 < len(selected["publicKeyPem"]) <= 4096)
    raw = selected["publicKeyPem"].encode("ascii")
    root = serialization.load_pem_public_key(raw)
    require(isinstance(root, Ed25519PublicKey)
        and root.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo) == raw
        and sha256(raw) == digest(selected["publicKeyPemSha256"])
        and sha256(_spki(root)) == digest(selected["publicKeySpkiSha256"]))
    envelope = _original(value["configurationOriginal"], contract.MAX_REQUEST_BYTES, exact=False)
    require(set(envelope) == {"schema", "payload", "signature"} and envelope["schema"] == SIGNED_CONFIGURATION)
    payload = envelope["payload"]
    require(type(payload) is dict and payload.get("schema") == configuration.CONFIGURATION_SCHEMA
        and payload.get("sourceRevision") == contract.SOURCE_REVISION and type(payload.get("roles")) is dict)
    root.verify(custody.decoded(envelope["signature"], 64, 64),
        commitment.framed_digest(SIGNED_CONFIGURATION, canonical(payload)).encode("ascii"))
    creation.validate_policy(payload.get(creation.FIELD), payload=payload, root_key=root)
    rotation.validate_policy(payload.get(rotation.FIELD), payload=payload, root_key=root)
    if rotation.FIELD in payload:
        current_policy.validate_policy(payload.get(current_policy.FIELD), payload=payload, root_key=root)
    selected = custody.validate_policy(payload.get(custody.FIELD), payload=payload, root_key=root)
    require(selected is not None and type(payload["roles"].get("planner")) is dict
        and {creation.OPERATION, rotation.OPERATION} & set(payload["roles"]["planner"].get("enabledOperations", ())))
    public = assignment.authorizer(selected["assignmentAuthorizer"], configuration_payload=payload,
        root_key=root, response_key_id=selected["target"]["controlPlaneResponseSigningKeyId"])
    return payload, root, selected, public


def _launch(value):
    original = _original(value, MAX_LAUNCH, exact=False)
    require(set(original) == LAUNCH_FIELDS and original["apiVersion"] == "catchplate.nativeStartupLaunch/v1")
    for name in ("releaseRecordSha256", "configurationSha256"):
        digest(original[name])
    require(type(original["deadlineBoottimeNs"]) is int and 0 < original["deadlineBoottimeNs"] < 2**64)
    for name in ("caNotBeforeUnixSeconds", "caNotAfterUnixSeconds", "ingressNotBeforeUnixSeconds", "ingressNotAfterUnixSeconds"):
        require(type(original[name]) is int and -(2**63) <= original[name] < 2**63)
    require(original["caNotBeforeUnixSeconds"] < original["caNotAfterUnixSeconds"]
        and original["caNotAfterUnixSeconds"] - original["caNotBeforeUnixSeconds"] <= 86400
        and original["caNotBeforeUnixSeconds"] <= original["ingressNotBeforeUnixSeconds"]
        < original["ingressNotAfterUnixSeconds"] <= original["caNotAfterUnixSeconds"])
    for name in ("ingressNonceBase64url", "proofNonceBase64url"):
        require(custody.decoded(original[name], 32, 32) != bytes(32))
    # This is guest BOOTTIME. Never compare it with, or rebase it onto, the
    # signer's clock. Actual native ownership checks the original deadline.
    return original


def _epoch_ns(value):
    delta = value - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (delta.days * 86400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1000


def _identity(original, selected, launch, expected_module, now):
    require(type(original) is str and original.isascii() and original.endswith("\n")
        and "\n" not in original[:-1] and len(original) <= MAX_IDENTITY)
    value = _original(original[:-1], MAX_IDENTITY - 1)
    require(set(value) == IDENTITY_FIELDS and value["apiVersion"] == IDENTITY_API
        and value["purpose"] == "postboot-static-assignment-inputs"
        and value["evidenceScope"] == "unverified-startup-role4-public-material"
        and value["okForAction"] is False)
    expected = selected["target"]
    scope = value["scope"]
    require(type(scope) is dict and set(scope) == set(SCOPE_FIELDS))
    for pin in scope.values(): digest(pin)
    require(scope["releaseRecordSha256"] == expected["releaseRecordSha256"] == launch["releaseRecordSha256"]
        and scope["policyHash"] == expected["policyHash"]
        and scope["configurationSha256"] == launch["configurationSha256"]
        and value["controlPlaneResponseSigningKeyId"] == expected["controlPlaneResponseSigningKeyId"])
    evidence = value["nativeKeyEvidence"]
    require(type(evidence) is dict and set(evidence) == {"apiVersion", "responseProofPublicKey", "attestationDocumentB64"}
        and evidence["apiVersion"] == "catchplate.nativeResponseProofKeyEvidence/v1")
    raw_key = custody.decoded(evidence["responseProofPublicKey"], 32, 32)
    require(raw_key != bytes(32))
    key = Ed25519PublicKey.from_public_bytes(raw_key)
    require(value["keyId"] == sha256(_spki(key)) and value["publicKeyPem"] == key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii"))
    boot = custody.decoded(value["bootId"], 32, 32)
    require(boot != bytes(32))
    ca_raw = custody.decoded(value["caCertificateDerBase64url"], 16 * 1024)
    ca = x509.load_der_x509_certificate(ca_raw)
    require(ca.public_bytes(serialization.Encoding.DER) == ca_raw and nitro.basic_constraints(ca, "native workload CA").ca
        and sha256(ca_raw) == scope["caCertificateSha256"] and sha256(_spki(ca.public_key())) == scope["caPublicKeySpkiSha256"])
    ca_begin, ca_end = (_epoch_ns(nitro.certificate_time(ca, name)) for name in ("not_valid_before", "not_valid_after"))
    require(ca_begin == launch["caNotBeforeUnixSeconds"] * 1_000_000_000
        and ca_end == launch["caNotAfterUnixSeconds"] * 1_000_000_000 and ca_begin <= now < ca_end)
    binding = hashlib.sha256(b"catchplate/native-proof-custody-boot/v1\0" + boot
        + bytes.fromhex(value["keyId"][7:]) + bytes.fromhex(expected["controlPlaneResponseSigningKeyId"][7:])).digest()
    user_data = b"catchplate/enclave-runtime-key-binding/v1\0\x04" + b"".join(
        bytes.fromhex(scope[name][7:]) for name in SCOPE_FIELDS) + hashlib.sha256(raw_key).digest() + binding
    require(custody.decoded(value["quoteUserDataBase64url"], 1024) == user_data)
    nonce = custody.decoded(value["quoteNonceBase64url"], 32, 32)
    require(nonce == custody.decoded(launch["proofNonceBase64url"], 32, 32))
    roots, crls, cert_profile = custody._trust(selected["trustRoots"])
    verified, quote_issued, _, leaf, root = nitro._verify_nitro_document_common(
        custody.decoded(evidence["attestationDocumentB64"], 12 * 1024), claims=None,
        expected_user_data_bytes=user_data, challenge=nonce, expected_pcrs=expected["expectedPcrs"],
        expected_eif=expected["expectedEif"], roots=roots, crls=crls, certificate_profile=cert_profile,
        expected_module_id=expected_module, now=now // 1_000_000_000, max_age=expected["maxAgeSeconds"],
        future_skew=expected["futureSkewSeconds"], native_profile=True)
    require(type(verified["public_key"]) is bytes and verified["public_key"] == raw_key)
    require(launch["ingressNotBeforeUnixSeconds"] * 1000 <= verified["timestamp"]
        < launch["ingressNotAfterUnixSeconds"] * 1000,
        "Startup quote was not issued inside the original launch ingress interval")
    # The entire cabundle was authenticated above, including no unused members.
    # Retain its earliest original expiry across key access and pipe output.
    certs = [ca, leaf, root] + [x509.load_der_x509_certificate(raw) for raw in verified["cabundle"]]
    evidence_expires = min((quote_issued + expected["maxAgeSeconds"]) * 1_000_000_000,
        *(_epoch_ns(nitro.certificate_time(cert, "not_valid_after")) for cert in certs))
    require(now < evidence_expires)
    dynamic = {"holderId": current.holder_id(value["bootId"], value["keyId"]),
        "bootId": value["bootId"], "keyId": value["keyId"],
        "configurationSha256": scope["configurationSha256"],
        "caCertificateSha256": scope["caCertificateSha256"], "caPublicKeySpkiSha256": scope["caPublicKeySpkiSha256"],
        "expectedModuleId": verified["module_id"]}
    require(set(dynamic) == assignment.DYNAMIC_FIELDS)
    return dynamic, evidence_expires, ca_begin, ca_end


@dataclass(frozen=True)
class Prepared:
    """Private signing preparation, never a native liveness/admission receipt."""
    payload_original: bytes
    configuration_original: bytes
    root: Ed25519PublicKey
    public_key: Ed25519PublicKey
    issued: int
    expires: int

    def check_time(self, now):
        require(type(now) is int and self.issued <= now < self.expires)


def prepare_input(raw, *, now_epoch_ns):
    value = document(raw, MAX_INPUT)
    require(set(value) == FIELDS and value["apiVersion"] == API)
    issued, expires = value["issuedAtEpochNs"], value["expiresAtEpochNs"]
    require(type(now_epoch_ns) is int and type(issued) is int and type(expires) is int
        and 0 < issued <= now_epoch_ns < expires <= 2**63 - 1
        and expires - issued <= assignment.MAX_INTERVAL_NS)
    expected_module = value["expectedModuleId"]
    require(type(expected_module) is str and 1 <= len(expected_module) <= 256)
    authority, root, selected, public = _configuration(value)
    dynamic, evidence_expires, ca_begin, ca_end = _identity(value["nativeIdentityOriginal"], selected,
        _launch(value["nativeLaunchOriginal"]), expected_module, now_epoch_ns)
    require(ca_begin <= issued < expires <= ca_end,
        "The approved assignment interval exceeds the original native CA lifetime")
    item = {**selected["target"], **dynamic}
    require(item["keyId"] not in assignment.excluded_keys(authority, root)
        | {item["controlPlaneResponseSigningKeyId"], selected["assignmentAuthorizer"]["publicKeySpkiSha256"]})
    payload = {"schema": assignment.SCHEMA, "controlPlaneConfigurationDigest": configuration.full_configuration_digest(authority),
        "deploymentId": selected["deploymentId"], "assignment": item, "issuedAtEpochNs": issued, "expiresAtEpochNs": expires}
    # Unsigned closed-shape preflight only; the zero slot is never authority or
    # emitted. Real signature verification below precedes any signed output.
    preflight = canonical({"schema": assignment.SIGNED_SCHEMA, "payload": payload,
        "signature": base64.urlsafe_b64encode(bytes(64)).rstrip(b"=").decode("ascii")}).decode("ascii")
    require(assignment.original(preflight)["payload"] == payload)
    return Prepared(canonical(payload), canonical(authority), root, public, issued, min(expires, evidence_expires))


def sign(raw, key, *, check):
    # Never accept a caller-constructed preparation/verdict as signing authority.
    # Repeat the original signature/evidence joins at the existing owner's time;
    # this does not select a new interval or renew its retained local budget.
    require(isinstance(key, Ed25519PrivateKey) and callable(check))
    prepared = prepare_input(raw, now_epoch_ns=check())
    require(_spki(key.public_key()) == _spki(prepared.public_key))
    prepared.check_time(check())
    signature = key.sign(commitment.framed_digest(assignment.SIGNED_SCHEMA, prepared.payload_original).encode("ascii"))
    prepared.check_time(check())
    payload = document(prepared.payload_original, assignment.MAX_ORIGINAL_BYTES)
    result = canonical({"schema": assignment.SIGNED_SCHEMA, "payload": payload,
        "signature": base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")})
    require(len(result) <= assignment.MAX_ORIGINAL_BYTES)
    verified = assignment.verify_original(result.decode("ascii"),
        configuration_payload=document(prepared.configuration_original, contract.MAX_REQUEST_BYTES),
        root_key=prepared.root, now_epoch_ns=check())
    require(canonical(verified) == prepared.payload_original)
    prepared.check_time(check())
    return result
