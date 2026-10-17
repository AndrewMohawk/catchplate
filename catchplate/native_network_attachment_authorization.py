"""Separately signed, original-only static bridge/veth attachment constraints.

This module authenticates a grant, not a bridge, child, proof or effect. The
native owner must join the actual v3 egress authorization and same-session
originals, protected token, preprovisioned bridge/lock and creation/kernel owners.
No application start, host routing/NAT change or recovery is authorized here.
"""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from catchplate import native_egress_installation_authorization as egress
from catchplate import native_enrollment_assignment as assignment
from catchplate import native_enrollment_bootstrap_setup as setup
from catchplate import workload_identity_issuer_bootstrap as shared
from catchplate_agent_trust import _workload_signed_packet as packets
from catchplate_agent_trust import workload_identity_bootstrap_originals as bootstrap


SCHEMA = "catchplate.signedNativeNetworkAttachmentAuthorization/v1"
PAYLOAD_SCHEMA = "catchplate.nativeNetworkAttachmentAuthorization/v1"
PURPOSE = "native-network-attachment"
PROFILE = "rtnetlink-veth-bridge-static-v1"
MAX_BYTES = 32 * 1024
MAX_KEY_BYTES = 16 * 1024
MAX_LIFETIME_NS = 300_000_000_000
_FIELDS = frozenset({
    "schema", "sourceRevision", "purpose", "trustMode", "authorizationId",
    "egressAuthorizationSha256", "launchManifestSha256", "setupSha256", "delegationSha256",
    "targetRequestSha256", "policyRequirementsSha256", "releaseRecordSha256", "policyHash",
    "configurationSha256", "runtimeCaCertificateSha256", "runtimeCaSpkiSha256",
    "ingressLeafCertificateSha256", "clientTrustBundleSha256", "clientChallengeSha256",
    "targetSpkiSha256", "machineIdSha256", "targetPrincipalId", "targetNonce", "networkOwner",
    "bridge", "attachment", "capability", "journal", "issuedAtEpochNs", "expiresAtEpochNs",
})
_DIGEST_FIELDS = (
    "egressAuthorizationSha256", "launchManifestSha256", "setupSha256", "delegationSha256",
    "targetRequestSha256", "policyRequirementsSha256", "releaseRecordSha256", "policyHash",
    "configurationSha256", "runtimeCaCertificateSha256", "runtimeCaSpkiSha256",
    "ingressLeafCertificateSha256", "clientTrustBundleSha256", "clientChallengeSha256",
    "targetSpkiSha256", "machineIdSha256",
)
_INTERFACE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}\Z")
_MAC = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\Z")
_CAPABILITY = re.compile(r"[A-Za-z0-9_-]{24,128}\Z")


class NativeNetworkAttachmentAuthorizationError(ValueError):
    pass


def _fail():
    raise NativeNetworkAttachmentAuthorizationError("native network attachment authorization is invalid")


@dataclass(frozen=True, slots=True, repr=False)
class _AttachmentAuthorizationMaterial:
    authorization_bytes: bytes
    authorization_digest: str
    payload_bytes: bytes
    root_pem_digest: str
    root_spki_digest: str
    authorization_id: str
    issued_at_epoch_ns: int
    expires_at_epoch_ns: int
    window: tuple
    deadline_ns: int
    live: object


def _interface(value):
    if type(value) is not str or _INTERFACE.fullmatch(value) is None:
        _fail()


def _mac(value):
    if type(value) is not str or _MAC.fullmatch(value) is None:
        _fail()
    raw = bytes.fromhex(value.replace(":", ""))
    if not any(raw) or raw[0] & 1:
        _fail()


def _ip(value):
    assignment._ascii(value, 45)
    if "%" in value:
        _fail()
    address = ipaddress.ip_address(value)
    if (str(address) != value or address.is_unspecified or address.is_multicast
            or isinstance(address, ipaddress.IPv4Address) and int(address) == 0xFFFFFFFF
            or isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None):
        _fail()
    return address


def _path(value):
    path = assignment._ascii(value, 4096)
    parts = path[1:].split("/")
    if (not path.startswith("/") or path == "/" or "\\" in path or len(parts) > 64
            or any(part in ("", ".", "..") or len(part) > 255 for part in parts)):
        _fail()


def _plan(bridge, attachment, budget):
    shared._object(bridge, {"name", "ifindex", "macAddress", "mtu", "kind", "lock"})
    _interface(bridge["name"])
    shared._integer(bridge["ifindex"], (1 << 31) - 1, 1)
    _mac(bridge["macAddress"])
    shared._integer(bridge["mtu"], 65535, 1280)
    if bridge["kind"] != "bridge":
        _fail()
    lock = shared._object(bridge["lock"], {"path", "device", "inode"})
    _path(lock["path"])
    shared._integer(lock["device"], minimum=1)
    shared._integer(lock["inode"], minimum=1)
    shared._object(attachment, {"profile", "hostVethName", "childVethName", "mtu",
        "hostMacAddress", "childMacAddress", "addresses", "routes"})
    if attachment["profile"] != PROFILE:
        _fail()
    for field in ("hostVethName", "childVethName"):
        _interface(attachment[field])
    if len({bridge["name"], attachment["hostVethName"], attachment["childVethName"]}) != 3:
        _fail()
    shared._integer(attachment["mtu"], bridge["mtu"], 1280)
    for field in ("hostMacAddress", "childMacAddress"):
        _mac(attachment[field])
    if len({bridge["macAddress"], attachment["hostMacAddress"], attachment["childMacAddress"]}) != 3:
        _fail()
    addresses = attachment["addresses"]
    routes = attachment["routes"]
    if type(addresses) is not list or not 1 <= len(addresses) <= 2:
        _fail()
    selected = {}
    previous = None
    for value in addresses:
        budget.check()
        shared._object(value, {"family", "address", "prefixLength"})
        address = _ip(value["address"])
        family = "ipv4" if address.version == 4 else "ipv6"
        width = 32 if address.version == 4 else 128
        shared._integer(value["prefixLength"], width, width)
        key = (address.version, address.packed)
        if value["family"] != family or family in selected or previous is not None and key <= previous:
            _fail()
        selected[family] = address
        previous = key
    if type(routes) is not list or not 1 <= len(routes) <= 16:
        _fail()
    previous = None
    used = set()
    for value in routes:
        budget.check()
        shared._object(value, {"family", "destination", "gateway", "gatewayMacAddress"})
        destination = _ip(value["destination"])
        gateway = _ip(value["gateway"])
        family = "ipv4" if destination.version == 4 else "ipv6"
        key = (destination.version, destination.packed)
        if (value["family"] != family or gateway.version != destination.version
                or family not in selected or selected[family] in (destination, gateway)
                or previous is not None and key <= previous
                or value["gatewayMacAddress"] != bridge["macAddress"]):
            _fail()
        previous = key
        used.add(family)
    if used != set(selected):
        _fail()
    budget.check()


def _payload(value, budget):
    shared._object(value, _FIELDS)
    if (value["schema"] != PAYLOAD_SCHEMA or value["sourceRevision"] != shared.authority.SOURCE_REVISION
            or value["purpose"] != PURPOSE or value["trustMode"] != "trusted-host-local"):
        _fail()
    shared._identifier(value["authorizationId"])
    for field in _DIGEST_FIELDS:
        assignment._digest(value[field])
    bootstrap._expectations(value["targetPrincipalId"], value["targetNonce"])
    setup._network_owner(value["networkOwner"])
    if value["networkOwner"]["ownerUid"] != 0:
        _fail()
    _plan(value["bridge"], value["attachment"], budget)
    capability = shared._object(value["capability"],
        {"capabilityId", "capabilityTokenSha256", "expiresAtEpochMs"})
    if type(capability["capabilityId"]) is not str or _CAPABILITY.fullmatch(capability["capabilityId"]) is None:
        _fail()
    assignment._digest(capability["capabilityTokenSha256"])
    expiry_ms = shared._integer(capability["expiresAtEpochMs"], bootstrap.MAX_EPOCH_MS, 1)
    egress._journal(value["journal"])
    journal = value["journal"]
    lock = value["bridge"]["lock"]
    if (lock["path"] == journal["path"]
            or (lock["device"], lock["inode"]) == (journal["device"], journal["inode"])):
        _fail()
    issued = shared._integer(value["issuedAtEpochNs"], minimum=1)
    expires = shared._integer(value["expiresAtEpochNs"], minimum=issued + 1)
    if expires - issued > MAX_LIFETIME_NS or expires > expiry_ms * 1_000_000:
        _fail()
    budget.interval(issued, expires)


def _admit(original, public, root_pin, budget):
    egress._structure(original, budget)
    payload = shared._signed(original, SCHEMA, PAYLOAD_SCHEMA, public, MAX_BYTES, budget)
    _payload(payload, budget)
    material = _AttachmentAuthorizationMaterial(
        authorization_bytes=original, authorization_digest=packets._digest(original, budget),
        payload_bytes=packets._canonical(payload, MAX_BYTES, budget), root_pem_digest=root_pin,
        root_spki_digest=packets._digest(shared._spki(public, budget), budget),
        authorization_id=payload["authorizationId"], issued_at_epoch_ns=payload["issuedAtEpochNs"],
        expires_at_epoch_ns=payload["expiresAtEpochNs"], window=budget.window,
        deadline_ns=budget.bound, live=budget.current)
    material.live()
    return material


def _verify_on_work(*, authorization_bytes, root_public_key_bytes, expected_root_pem_sha256,
        work, live_window, transport_deadline_ns, _current=None, _additional_original_bytes=0):
    """Authenticate original constraints under the caller's existing work/clock."""
    try:
        egress._preflight(((authorization_bytes, MAX_BYTES), (root_public_key_bytes, MAX_KEY_BYTES)),
            work, _additional_original_bytes)
        budget = shared._Budget(work, live_window, transport_deadline_ns, _current)
        public = assignment._public_key(root_public_key_bytes, expected_root_pem_sha256, budget)
        return _admit(authorization_bytes, public, expected_root_pem_sha256, budget)
    except NativeNetworkAttachmentAuthorizationError:
        raise
    except Exception:
        raise NativeNetworkAttachmentAuthorizationError("native network attachment authorization verification failed") from None


def _produce_on_work(*, payload_bytes, root_private_key_bytes, root_public_key_bytes,
        expected_root_pem_sha256, work, live_window, transport_deadline_ns,
        _current=None, _additional_original_bytes=0):
    """Explicit canonical PKCS8 original, no files, key generation or effects."""
    try:
        egress._preflight(((payload_bytes, MAX_BYTES), (root_private_key_bytes, MAX_KEY_BYTES),
            (root_public_key_bytes, MAX_KEY_BYTES)), work, _additional_original_bytes, producing=True)
        budget = shared._Budget(work, live_window, transport_deadline_ns, _current)
        public = assignment._public_key(root_public_key_bytes, expected_root_pem_sha256, budget)
        egress._structure(payload_bytes, budget)
        payload = shared._decode(payload_bytes, MAX_BYTES, budget)
        _payload(payload, budget)
        budget.charge(input_bytes=len(root_private_key_bytes))
        private = serialization.load_pem_private_key(root_private_key_bytes, password=None)
        budget.check()
        if (not isinstance(private, ed25519.Ed25519PrivateKey)
                or private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption()) != root_private_key_bytes
                or shared._spki(private.public_key(), budget) != shared._spki(public, budget)):
            _fail()
        original = shared._produce(payload_bytes, SCHEMA, PAYLOAD_SCHEMA,
            private, public, MAX_BYTES, budget)
        admitted = _admit(original, public, expected_root_pem_sha256, budget)
        admitted.live()
        budget.check()
        return original
    except NativeNetworkAttachmentAuthorizationError:
        raise
    except Exception:
        raise NativeNetworkAttachmentAuthorizationError("native network attachment authorization production failed") from None
