"""Explicit independently signed public native-bootstrap setup associations.

Both entrypoints re-admit delegation and target request originals. Requirements
bytes are only a signed selected commitment, never proof of a current Snapshot.
No capability token, namespace ownership, installation, issuer grant, native
signature, durable claim or packet-verification verdict is created here.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import ipaddress
import re
from urllib.parse import urlsplit
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from serverware import native_enrollment_assignment as assignment
from serverware import native_enrollment_bootstrap_delegation as delegation
from serverware_agent_trust import _workload_signed_packet as packets


SCHEMA = "serverware.signedNativeEnrollmentBootstrapSetup/v1"
PAYLOAD_SCHEMA = "serverware.nativeEnrollmentBootstrapSetup/v1"
PURPOSE = "native-enrollment-bootstrap-setup"
SIGNATURE_DOMAIN = b"serverware/native-enrollment-bootstrap-setup/v1\x00"
MAX_BYTES = MAX_PAYLOAD_BYTES = 32 * 1024
MAX_KEY_BYTES = assignment.MAX_KEY_BYTES
MAX_REQUIREMENTS_BYTES = 64 * 1024
MAX_ORIGINAL_BYTES = assignment.MAX_ORIGINAL_BYTES
MAX_JSON_DEPTH = 4
shared = assignment.shared
_FIELDS = frozenset({
    "apiVersion", "purpose", "authorizerKeyId", "setupId", "delegationSha256",
    "targetRequestSha256", "releaseRecordSha256", "policyHash", "configurationSha256",
    "runtimeCaCertificateSha256", "runtimeCaSpkiSha256", "policyRequirementsSha256",
    "targetPrincipalId", "targetNonce", "controlPlaneOrigin", "proxy", "caInstall",
    "kubernetes", "networkOwner", "notBeforeUnixSeconds", "expiresAtUnixSeconds",
})
_DIGEST_FIELDS = (
    "authorizerKeyId", "delegationSha256", "targetRequestSha256", "releaseRecordSha256",
    "policyHash", "configurationSha256", "runtimeCaCertificateSha256",
    "runtimeCaSpkiSha256", "policyRequirementsSha256",
)
_LABEL = re.compile(r"[A-Za-z0-9](?:[-_.A-Za-z0-9]{0,61}[A-Za-z0-9])?\Z")
_CAPABILITY = re.compile(r"[A-Za-z0-9_-]{24,128}\Z")
_HOST_ID = re.compile(r"[A-Za-z0-9._:-]{1,128}\Z")


class NativeEnrollmentBootstrapSetupError(ValueError):
    pass


def _fail():
    raise NativeEnrollmentBootstrapSetupError("native enrollment bootstrap setup is invalid")


def _construction_on_work(work):
    return assignment._construction_on_work(work)


@dataclass(frozen=True, slots=True, repr=False)
class _SetupMaterial:
    setup_digest: str
    authorizer_key_id: str
    setup_id: str
    delegation_digest: str
    target_request_digest: str
    policy_requirements_digest: str
    payload_bytes: bytes
    window: tuple
    deadline_ns: int
    live: object


def _unicast(value):
    assignment._ascii(value, 64)
    address = ipaddress.ip_address(value)
    selected = address.ipv4_mapped if isinstance(address, ipaddress.IPv6Address) else None
    selected = address if selected is None else selected
    if (assignment._ip_spelling(address) != value or selected.is_unspecified
            or selected.is_multicast or selected == ipaddress.IPv4Address("255.255.255.255")):
        _fail()
    return address


def _origin(value):
    assignment._ascii(value, 2048)
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or parsed.username is not None or parsed.password is not None
            or parsed.path or parsed.query or parsed.fragment or parsed.hostname is None):
        _fail()
    host = parsed.hostname
    assignment._host(host)
    port = parsed.port if parsed.port is not None else 443
    if not 1 <= port <= 65535:
        _fail()
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        # Match the native URL parser's ends-in-number rule: short decimal,
        # octal and hexadecimal IPv4 spellings are not alternate DNS origins.
        final_label = host.rsplit(".", 1)[-1]
        if final_label.isdecimal() or re.fullmatch(r"0x[0-9a-f]*", final_label):
            _fail()
        authority = host
    else:
        _unicast(host)
        authority = "[" + host + "]" if address.version == 6 else host
    expected = "https://" + authority + (":" + str(port) if port != 443 else "")
    if value != expected:
        _fail()
    return host, port


def _ordered_strings(value, maximum):
    if (type(value) is not list or not 1 <= len(value) <= maximum
            or any(type(item) is not str or not item.isascii() for item in value)
            or value != sorted(set(value))):
        _fail()


def _proxy(value, admitted):
    shared._object(value, {"origin", "endpoint", "egressCidrs", "hostAddresses"})
    host, port = _origin(value["origin"])
    assignment._endpoint(value["endpoint"])
    if value["endpoint"] != admitted.proxy_endpoint or host != admitted.ingress_host:
        _fail()
    endpoint_host, endpoint_port = value["endpoint"].rsplit(":", 1)
    endpoint_host = endpoint_host[1:-1] if endpoint_host.startswith("[") else endpoint_host
    if port != int(endpoint_port):
        _fail()
    selected = _unicast(endpoint_host)
    _ordered_strings(value["egressCidrs"], 32)
    networks = []
    for original in value["egressCidrs"]:
        assignment._ascii(original, 80)
        network = ipaddress.ip_network(original, strict=True)
        if (network.prefixlen == 0 or original != assignment._ip_spelling(network.network_address)
                + "/" + str(network.prefixlen)):
            _fail()
        networks.append(network)
    _ordered_strings(value["hostAddresses"], 16)
    addresses = [_unicast(original) for original in value["hostAddresses"]]
    if selected not in addresses or any(not any(address in net for net in networks) for address in addresses):
        _fail()
    try:
        origin_ip = ipaddress.ip_address(host)
    except ValueError:
        return
    if addresses != [selected] or origin_ip != selected:
        _fail()


def _kubernetes(value):
    if value is None:
        return
    shared._object(value, {"namespace", "podSelector"})
    namespace = value["namespace"]
    if type(namespace) is not str or assignment._DNS_LABEL.fullmatch(namespace) is None or len(namespace) > 63:
        _fail()
    selector = value["podSelector"]
    if type(selector) is not dict or not 1 <= len(selector) <= 16:
        _fail()
    for key, selected in selector.items():
        if type(key) is not str or type(selected) is not str:
            _fail()
        if "/" in key:
            prefix, name = key.split("/", 1)
            if not assignment._dns(prefix):
                _fail()
        else:
            name = key
        if _LABEL.fullmatch(name) is None or (selected and _LABEL.fullmatch(selected) is None):
            _fail()


def _install(value):
    shared._object(value, {"profile", "capabilityId", "capabilityTokenSha256", "expiresAtEpochMs",
        "destinationPath", "ownerUid", "ownerGid", "fileMode", "replaceExisting",
        "expectedExistingCertificateSha256"})
    if (value["profile"] != "native-ca-install-association-v1"
            or type(value["capabilityId"]) is not str or _CAPABILITY.fullmatch(value["capabilityId"]) is None):
        _fail()
    assignment._digest(value["capabilityTokenSha256"])
    expires = shared._integer(value["expiresAtEpochMs"], delegation.bootstrap.MAX_EPOCH_MS, 1)
    path = assignment._ascii(value["destinationPath"], 4096)
    if (not path.startswith("/") or "\\" in path
            or any(part in ("", ".", "..") for part in path[1:].split("/"))):
        _fail()
    for field in ("ownerUid", "ownerGid"):
        shared._integer(value[field], (1 << 32) - 2)
    if type(value["fileMode"]) is not int or value["fileMode"] != 420 or type(value["replaceExisting"]) is not bool:
        _fail()
    if value["replaceExisting"]:
        assignment._digest(value["expectedExistingCertificateSha256"])
    elif value["expectedExistingCertificateSha256"] is not None:
        _fail()
    return expires


def _network_owner(value):
    shared._object(value, {"hostId", "bootId", "namespaceDevice", "namespaceInode", "ownerUid"})
    if type(value["hostId"]) is not str or _HOST_ID.fullmatch(value["hostId"]) is None:
        _fail()
    boot = value["bootId"]
    if type(boot) is not str or len(boot) != 36:
        _fail()
    parsed = uuid.UUID(boot)
    if not parsed.int or str(parsed) != boot:
        _fail()
    shared._integer(value["namespaceDevice"], (1 << 64) - 1)
    shared._integer(value["namespaceInode"], (1 << 64) - 1, 1)
    shared._integer(value["ownerUid"], (1 << 32) - 2)


def _payload(value, public, admitted, requirements, budget):
    shared._object(value, _FIELDS)
    if value["apiVersion"] != PAYLOAD_SCHEMA or value["purpose"] != PURPOSE:
        _fail()
    for field in _DIGEST_FIELDS:
        assignment._digest(value[field])
    assignment._identifier(value["setupId"])
    delegation.bootstrap._expectations(value["targetPrincipalId"], value["targetNonce"])
    expected = {
        "delegationSha256": admitted.delegation_digest,
        "targetRequestSha256": admitted.target_request_sha256,
        "releaseRecordSha256": admitted.release_record_sha256,
        "policyHash": admitted.policy_hash, "configurationSha256": admitted.configuration_sha256,
        "runtimeCaCertificateSha256": admitted.runtime_ca_certificate_sha256,
        "runtimeCaSpkiSha256": admitted.runtime_ca_spki_sha256,
        "targetPrincipalId": admitted.target_principal_id, "targetNonce": admitted.target_nonce,
        "policyRequirementsSha256": packets._digest(requirements, budget),
    }
    if any(value[field] != expected_value for field, expected_value in expected.items()):
        _fail()
    key_id = packets._digest(shared._spki(public, budget), budget)
    if value["authorizerKeyId"] != key_id or key_id in (
            admitted.authorizer_key_id, admitted.runtime_ca_spki_sha256,
            admitted.caller_issuer_spki_sha256, admitted.caller_spki_sha256,
            admitted.target_issuer_spki_sha256, admitted.target_spki_sha256):
        _fail()
    _origin(value["controlPlaneOrigin"])
    _proxy(value["proxy"], admitted)
    capability_expires = _install(value["caInstall"])
    _kubernetes(value["kubernetes"])
    _network_owner(value["networkOwner"])
    issued = shared._integer(value["notBeforeUnixSeconds"], assignment.MAX_EPOCH_SECONDS, 1)
    expires = shared._integer(value["expiresAtUnixSeconds"], assignment.MAX_EPOCH_SECONDS, issued + 1)
    if (expires - issued > assignment.MAX_INTERVAL_SECONDS
            or issued < admitted.not_before_unix_seconds or expires > admitted.expires_at_unix_seconds
            or issued * 1000 < admitted.target_created_at_epoch_ms
            or expires * 1000 > min(admitted.target_expires_at_epoch_ms, capability_expires)):
        _fail()
    budget.interval(issued * 1_000_000_000, expires * 1_000_000_000)
    admitted.live()
    budget.check()


def _admit(original, public, admitted, requirements, budget):
    if not original.endswith(b"\n"):
        _fail()
    envelope = delegation._decode(original[:-1], MAX_BYTES - 1, budget)
    shared._object(envelope, {"apiVersion", "setup", "signatureBase64url"})
    if envelope["apiVersion"] != SCHEMA or type(envelope["setup"]) is not dict:
        _fail()
    payload = envelope["setup"]
    payload_bytes = packets._canonical(payload, MAX_PAYLOAD_BYTES, budget)
    signature = assignment._base64(envelope["signatureBase64url"], 64)
    message = SIGNATURE_DOMAIN + payload_bytes
    budget.charge(input_bytes=len(message), hashes=1)
    public.verify(signature, message)
    budget.check()
    _payload(payload, public, admitted, requirements, budget)

    def live():
        admitted.live()
        return budget.current()

    result = _SetupMaterial(packets._digest(original, budget), payload["authorizerKeyId"],
        payload["setupId"], admitted.delegation_digest, admitted.target_request_sha256,
        payload["policyRequirementsSha256"], payload_bytes, budget.window, budget.bound, live)
    live()
    return result


def _context(originals, additional, work, window, bound, current, setup_public, setup_pin,
        delegation_original, delegation_public, delegation_pin, request, issuer, *, producing=False):
    delegation._preflight(originals, additional, work, producing=producing)
    budget = assignment._Lifetime(work, window, bound, current)
    public = assignment._public_key(setup_public, setup_pin, budget)
    original_authorizer = assignment._public_key(delegation_public, delegation_pin, budget)
    admitted = delegation._admit(delegation_original, original_authorizer, request, issuer, budget)
    return budget, public, admitted


def _verify_on_work(*, setup_bytes, setup_public_key_bytes, expected_setup_pem_sha256,
        delegation_bytes, delegation_public_key_bytes, expected_delegation_pem_sha256,
        target_request_bytes, target_issuer_certificate_bytes, policy_requirements_bytes,
        work, live_window, transport_deadline_ns, _current=None, _additional_original_bytes=0):
    """Verify original signatures/data only; no live runtime or install receipt."""
    try:
        originals = ((setup_bytes, MAX_BYTES), (setup_public_key_bytes, MAX_KEY_BYTES),
            (delegation_bytes, delegation.MAX_BYTES), (delegation_public_key_bytes, MAX_KEY_BYTES),
            (target_request_bytes, delegation.MAX_REQUEST_BYTES),
            (target_issuer_certificate_bytes, delegation.MAX_ISSUER_BYTES),
            (policy_requirements_bytes, MAX_REQUIREMENTS_BYTES))
        budget, public, admitted = _context(originals, _additional_original_bytes, work,
            live_window, transport_deadline_ns, _current, setup_public_key_bytes,
            expected_setup_pem_sha256, delegation_bytes, delegation_public_key_bytes,
            expected_delegation_pem_sha256, target_request_bytes, target_issuer_certificate_bytes)
        return _admit(setup_bytes, public, admitted, policy_requirements_bytes, budget)
    except NativeEnrollmentBootstrapSetupError:
        raise
    except Exception:
        raise NativeEnrollmentBootstrapSetupError("native enrollment bootstrap setup verification failed") from None


def _produce_on_work(*, payload_bytes, setup_private_key_bytes, setup_public_key_bytes,
        expected_setup_pem_sha256, delegation_bytes, delegation_public_key_bytes,
        expected_delegation_pem_sha256, target_request_bytes, target_issuer_certificate_bytes,
        policy_requirements_bytes, work, live_window, transport_deadline_ns,
        _current=None, _additional_original_bytes=0):
    """Explicit canonical PKCS8 authorizer input; no key lookup or generation."""
    try:
        originals = ((payload_bytes, MAX_PAYLOAD_BYTES), (setup_private_key_bytes, MAX_KEY_BYTES),
            (setup_public_key_bytes, MAX_KEY_BYTES), (delegation_bytes, delegation.MAX_BYTES),
            (delegation_public_key_bytes, MAX_KEY_BYTES), (target_request_bytes, delegation.MAX_REQUEST_BYTES),
            (target_issuer_certificate_bytes, delegation.MAX_ISSUER_BYTES),
            (policy_requirements_bytes, MAX_REQUIREMENTS_BYTES))
        budget, public, admitted = _context(originals, _additional_original_bytes, work,
            live_window, transport_deadline_ns, _current, setup_public_key_bytes,
            expected_setup_pem_sha256, delegation_bytes, delegation_public_key_bytes,
            expected_delegation_pem_sha256, target_request_bytes, target_issuer_certificate_bytes, producing=True)
        payload = delegation._decode(payload_bytes, MAX_PAYLOAD_BYTES, budget)
        _payload(payload, public, admitted, policy_requirements_bytes, budget)
        budget.charge(input_bytes=len(setup_private_key_bytes))
        private = serialization.load_pem_private_key(setup_private_key_bytes, password=None)
        budget.check()
        if (not isinstance(private, ed25519.Ed25519PrivateKey)
                or private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption()) != setup_private_key_bytes
                or shared._spki(private.public_key(), budget) != shared._spki(public, budget)):
            _fail()
        message = SIGNATURE_DOMAIN + payload_bytes
        admitted.live()
        budget.charge(input_bytes=len(message), hashes=1)
        signature = private.sign(message)
        budget.check()
        original = packets._canonical({"apiVersion": SCHEMA, "setup": payload,
            "signatureBase64url": base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")},
            MAX_BYTES - 1, budget) + b"\n"
        verified = _admit(original, public, admitted, policy_requirements_bytes, budget)
        verified.live()
        budget.check()
        return original
    except NativeEnrollmentBootstrapSetupError:
        raise
    except Exception:
        raise NativeEnrollmentBootstrapSetupError("native enrollment bootstrap setup production failed") from None
